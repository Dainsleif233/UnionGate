package proxiedproxy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// RSAKeyBits matches Java RSAUtil.KEY_SIZE (3072).
const RSAKeyBits = 3072

// GenerateRSAKeyPair generates an RSA key pair of the original's key size.
func GenerateRSAKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, RSAKeyBits)
}

// SignRSA signs body with SHA256withRSA (RSASSA-PKCS1-v1_5 over a SHA-256
// digest) and returns the base64 signature. Java RSAUtil.sign.
func SignRSA(body []byte, key *rsa.PrivateKey) (string, error) {
	if key == nil {
		return "", errors.New("nil private key")
	}
	digest := sha256.Sum256(body)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("rsa sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// ValidateRSA verifies a base64 SHA256withRSA signature over body.
// Java RSAUtil.validate.
func ValidateRSA(body []byte, sigBase64 string, key *rsa.PublicKey) error {
	if key == nil {
		return errors.New("nil public key")
	}
	sig, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return fmt.Errorf("invalid base64 signature: %w", err)
	}
	digest := sha256.Sum256(body)
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig)
}

// EncodePublicKeyPEM encodes a public key as X.509 SubjectPublicKeyInfo
// (PKIX) PEM, type "PUBLIC KEY", with 64-character base64 lines — the layout
// of Java RSAUtil.saveKeyPair.
func EncodePublicKeyPEM(key *rsa.PublicKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil public key")
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// EncodePrivateKeyPEM encodes a private key as PKCS#8 PEM, type
// "PRIVATE KEY", with 64-character base64 lines. Java RSAUtil.saveKeyPair.
func EncodePrivateKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("nil private key")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePublicKeyPEM parses an RSA public key from PEM text or bare base64 DER
// (the original strips PEM armor and newlines before decoding, so both forms
// are accepted). Java RSAUtil.convertStringToPublicKey.
func ParsePublicKeyPEM(s string) (*rsa.PublicKey, error) {
	der, err := decodePEMOrBase64(s)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return pub, nil
}

// ParsePrivateKeyPEM parses an RSA private key from PKCS#8 PEM text or bare
// base64 DER. Java RSAUtil.convertStringToPrivateKey.
func ParsePrivateKeyPEM(s string) (*rsa.PrivateKey, error) {
	der, err := decodePEMOrBase64(s)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	priv, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return priv, nil
}

// decodePEMOrBase64 extracts the DER bytes from a PEM block or, failing that,
// from bare base64 after stripping any PEM armor and whitespace.
func decodePEMOrBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if block, _ := pem.Decode([]byte(s)); block != nil {
		return block.Bytes, nil
	}
	stripped := stripPEMArmor(s)
	if stripped == "" {
		return nil, errors.New("empty key data")
	}
	der, err := base64.StdEncoding.DecodeString(stripped)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 key data: %w", err)
	}
	return der, nil
}

// stripPEMArmor removes PEM armor lines and all whitespace/newlines, like the
// original's replace-based unarmor.
func stripPEMArmor(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		b.WriteString(line)
	}
	return b.String()
}

// LoadPublicKeyPEM reads and parses a PEM public key file.
func LoadPublicKeyPEM(path string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKeyPEM(string(b))
}

// LoadPrivateKeyPEM reads and parses a PEM private key file.
func LoadPrivateKeyPEM(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKeyPEM(string(b))
}

// SavePublicKeyPEM writes a public key PEM file (0644).
func SavePublicKeyPEM(path string, key *rsa.PublicKey) error {
	enc, err := EncodePublicKeyPEM(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, enc, 0o644)
}

// SavePrivateKeyPEM writes a private key PEM file, readable only by the owner.
func SavePrivateKeyPEM(path string, key *rsa.PrivateKey) error {
	enc, err := EncodePrivateKeyPEM(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, enc, 0o600)
}

// TrustedEntryFile is one on-disk trusted entry record, in entry.json and as
// an element of the TrustedEntries.json array. Gson omits null fields, so
// exactly one of PublicKey/Key is present on the wire (omitempty replicates
// that; the PEM string embeds its armor and newlines, like the original).
type TrustedEntryFile struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey,omitempty"`
	Key       string `json:"key,omitempty"`
}

// MarshalEntryJSON encodes a trusted entry record as compact JSON.
func MarshalEntryJSON(e TrustedEntryFile) ([]byte, error) {
	return json.Marshal(e)
}

// ReadEntryJSON reads a single entry.json record.
func ReadEntryJSON(path string) (TrustedEntryFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return TrustedEntryFile{}, err
	}
	var e TrustedEntryFile
	if err := json.Unmarshal(b, &e); err != nil {
		return TrustedEntryFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return e, nil
}

// WriteEntryJSON writes a single entry.json record (overwrites, like the
// original FileWriter without append).
func WriteEntryJSON(path string, e TrustedEntryFile) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// ReadTrustedEntriesFile reads a TrustedEntries.json file: a JSON array of
// trusted entry records. An empty file ("null" after decode) yields no error
// and an empty list, mirroring the original Gson behavior.
func ReadTrustedEntriesFile(path string) ([]TrustedEntryFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []TrustedEntryFile
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return list, nil
}

// WriteTrustedEntriesFile writes the TrustedEntries.json array.
func WriteTrustedEntriesFile(path string, list []TrustedEntryFile) error {
	if list == nil {
		list = []TrustedEntryFile{}
	}
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// ToTrustedEntry parses the on-disk record into a runtime TrustedEntry. The
// record type decides the verification type, like Java TrustedEntry.getType.
func (f TrustedEntryFile) ToTrustedEntry() (*TrustedEntry, error) {
	switch {
	case f.PublicKey != "":
		pub, err := ParsePublicKeyPEM(f.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", f.ID, err)
		}
		return &TrustedEntry{PublicKey: pub}, nil
	case f.Key != "":
		return &TrustedEntry{Key: f.Key}, nil
	default:
		return nil, fmt.Errorf("entry %q: neither publicKey nor key set", f.ID)
	}
}

// LoadTrustedEntries reads a TrustedEntries.json file and builds the verifier
// entry map, keyed by entry id. Malformed or empty records are an error.
func LoadTrustedEntries(path string) (map[string]*TrustedEntry, error) {
	list, err := ReadTrustedEntriesFile(path)
	if err != nil {
		return nil, err
	}
	entries := make(map[string]*TrustedEntry, len(list))
	for _, f := range list {
		e, err := f.ToTrustedEntry()
		if err != nil {
			return nil, err
		}
		if f.ID == "" {
			return nil, errors.New("trusted entry with empty id")
		}
		entries[f.ID] = e
	}
	return entries, nil
}
