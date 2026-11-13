# UnionGate 使用文档

UnionGate = Gate（Go 版 Velocity 代理）+ 内嵌 frps + Union 插件集（mua / proxiedproxy / dimension / mapmod）+ Via 复用（vialite）。
玩家 → Gate（25565）→ 后端 MC 服；服主的服 → frpc → Gate 内嵌 frps → 自动注册成后端。

## 1. 快速启动

```bash
go build -o gate .
./gate --config config.yml
```

- 默认找工作目录 `config.yml`（或 `--config` 指定，`GATE_CONFIG` 环境变量亦可）。
- 日志 `--debug/-d`、`--verbosity/-v N`；版本 `--version/-V`；禁热重载 `--no-auto-reload`。
- 配置支持 yaml/json/env；`frps.token` 等建议走环境变量/secret 管理，不要明文入库。

## 2. 最小可用配置（单服 + MUA 动态服）

```yaml
config:
  bind: 0.0.0.0:25565
  servers:
    lobby:
      address: 127.0.0.1:25566
  try:
    - lobby

frps:
  enabled: true
  bindAddr: 0.0.0.0
  bindPort: 7001        # frpc 控制面；KCP 7002 / QUIC 7003 按需开，0=关
  #token: secret_here   # 生产必须设，空 token 会告警
  allowPorts: 10000-19999

union:
  mua:
    enabled: true
    #frpAddress: 127.0.0.1
    #restrictPort: false
    #allowMin: 10000
    #allowMax: 19999
```

启动后：服主用 frpc 连 `7001` 开隧道（remotePort 落在 allowPorts 内），隧道名即后端名，Gate 自动 `Register(name, frpAddress:remotePort)`；玩家进服按 `forced_hosts`/try 路由；隧道断开自动 `Unregister`。mua 要求 `frps.enabled: true`（Validate 强制）。

### frpc 侧（给服主的模板）

```ini
[common]
server_addr = <gate-ip>
server_port = 7001
token = secret_here
metas_domain = play.example.com
metas_forced_hosts = play.example.com
metas_domain_alias = lobby.example.com

[my-server]
type = tcp
local_ip = 127.0.0.1
local_port = 25566
remote_port = 10001
```

- `metas_domain`：该隧道域名；`metas_forced_hosts`：JSON 或单串，域名→后端映射；`metas_domain_alias`：别名。
- frps 收到 Login 带 metas 即回写 `mua_generation`；NewProxy 即注册；CloseProxy 即注销。
- MUA 拒绝串与 Kotlin 原版逐字一致（端口越界 / 非 TCP / 重名 / 端口占用）。

## 3. 各插件怎么用

### 3.1 mua（动态后端，必须开 frps）

`union.mua.enabled: true` + `frps.enabled: true`。`frpAddress` 是注册地址（玩家实际能连到 frps 出口的地址，默认 127.0.0.1，生产改公网 IP/域名解析到的地址）；`restrictPort` 开启则再用 `allowMin/allowMax` 卡一次端口（默认关，走 `frps.allowPorts`）。

### 3.2 proxiedproxy（ENTRY↔PROXY 链式转发）

对外提供域名、玩家从你这里 `/server` 进成员服的入口必须是 **ENTRY**；成员自己的 Velocity（接受入口连接的代理）是 **PROXY**。两者不能填反：入口填 PROXY/不填时，成员 PROXY 发来的 `proxied-proxy:login` 没人应答，核心回 `Success:false`，成员直接断开，日志只会显示 `BungeeCord IP forwarding` 的通用错误。

```yaml
# 对外入口（UnionEntryDocker 的替代）
union:
  proxiedProxy:
    role: ENTRY
    entryId: "<你的 UNION_ENTRY_ID>"
    verificationType: RSA
    # 复用旧 UnionEntryDocker 的密钥，成员的 TrustedEntries.json 才继续认你
    privateKeyPath: PrivateKey.pem
    publicKeyPath: PublicKey.pem
    entryJsonPath: entry.json
    serverCommandAlias: hub   # 原插件默认 hub；填 none 关闭
```

```yaml
# 成员服自己的 Velocity（接受入口连接）
union:
  proxiedProxy:
    role: PROXY
    trustedEntriesPath: TrustedEntries.json  # 放入入口的 entry.json
    #allowClientConnection: false
```

- ENTRY 启动自动生成/加载 RSA3072（`PrivateKey.pem 0600` + `PublicKey.pem` + `entry.json`），重启不轮换（D 值比对）。**换入口时必须复用旧 `PrivateKey.pem`/`entry.json`**；新密钥需要把新 `entry.json` 发给每个成员 PROXY 更新 `TrustedEntries.json`，否则验签失败。
- 入口 ENTRY 的 profile 序列化必须与 Java 逐字节兼容：`id` 用带连字符 UUID 且同时带 `undashedId`，JSON 按 Gson HTML-safe 转义（`< > & = '` → `\uXXXX`）。base64 皮肤值里的 `=` 若未转义，成员 PROXY 端 `profile.toString()` 会变成 `\u003d`，RSA 验签必然失败。
- PROXY 对上游 ENTRY `PreLogin` 发 `proxied-proxy:login/forward` 并强制离线鉴权；Verify 通过则 `GameProfileRequest` 换 profile + 记 forwardedAddr（登录窗口内生效，`PostLogin` 清理），失败记 `ok:false` 走 `PostLogin` 断开（坏包不再 panic，见 m02734 修）。
- `SendV1Verification` 仅为配置兼容保留，未实现（V1 签的是 Java GameProfile toString，无可移植定义）。

### 3.3 dimension（多服维度隔离，Xaero/VoxelMap 必开）

```yaml
union:
  dimension:
    enabled: true
```

`MapName(prefix, input)` 与 Java `mapName` byte-exact：`minecraft:overworld + lobby → minecraft:lobby_overworld`，无冒号则 `input+prefix`。按玩家当前服名改写 JoinGame/Respawn，进 backend_play + client_play 双调用点；`ServerPreConnect/Disconnect` 维护每玩家服名。

### 3.4 mapmod（地图 mod 世界 id 桥）

```yaml
union:
  mapMod:
    enabled: true
    #channels: []            # 空=默认四通道
    #forwardToBackend: false
```

默认通道（对 upstream Channels.java）：`xaerominimap:main`、`xaeroworldmap:main`、`worldinfo:world_id`、`world_id`。当前是 pass-through 桥（注册通道 + 放行 + 记录 world_id payload），不做 IdBlender 改写——per-server world 隔离尚未提供（见包 TODO）。

### 3.5 Via（老客户端进新服，复用 vialite）

```yaml
config:
  via:
    enabled: true   # 需非 Lite；首次启动下载 vialite artifact（要联网）
```

union 与 Via 无冲突（union 无 Via 引用）。hermetic 测试只能证到 artifact resolution 边界（`Offline + 不存在的 BinaryPath` fail-fast），不能离线真 boot——这是预期。

## 4. 完整配置段（copy-paste）

见 `config.yml:539-603`（`frps:` + `union:` 全段注释）。`config-simple/lite.yml` 只指回主模板。Lite 下 frps 照绑但隧道后端永不接客（只走 `lite.routes`），union/frps 会告警。

## 5. 验证（hermetic，不过网）

```bash
go build ./...
go vet ./pkg/gate/ ./pkg/union/ ./pkg/edition/java/proxy/
go test ./pkg/union/... -count=1
go test ./pkg/gate/ -count=1
```

关键用例：`TestStartupUnionFrpcMua`（真 frpc 进 embedded frps）、`TestLiveSignedForwardingRoundTrip`（RSA 全链路+篡改/过期/重放拒绝）、`TestStartupUnionFullStack`（frps+MUA+PROXY+dimension+mapmod 一次 boot）、Via 四件套（New 接线/Offline fail-fast/Lite 互斥）。

## 6. 边界与运维

- frps 关服时 third_party 一条 `InternalListener.Close DEBUG` 堆栈是上游原有日志，无害。
- unionsync 按要求忽略，未实现。
- 生产 checklist：`frps.token` 必设；`bindAddr` 收敛到内网；`allowPorts` 按需收窄；ENTRY 私钥 `0600` 保管好；`TrustedEntries.json` 手工分发 entry.json；改 `config.yml` 热重载只对 Lite routes 生效，其余改动要重启。
