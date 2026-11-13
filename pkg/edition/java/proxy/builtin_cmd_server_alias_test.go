package proxy

import "testing"

func TestRegisterServerCommandAlias(t *testing.T) {
	// A proxy created by New has a zero-value command.Manager; extensions may
	// register their alias before Proxy.Start/init, so the manager must be
	// usable at that point.
	p := &Proxy{}
	if err := p.RegisterServerCommandAlias("hub"); err != nil {
		t.Fatalf("register hub: %v", err)
	}
	if !p.command.Has("hub") {
		t.Fatal("hub alias was not registered")
	}

	for _, noop := range []string{"", "server", "none", "off"} {
		if err := p.RegisterServerCommandAlias(noop); err != nil {
			t.Fatalf("register %q: %v", noop, err)
		}
	}
	if p.command.Has("none") || p.command.Has("off") {
		t.Fatal("disabled alias names must not be registered")
	}

	if err := p.RegisterServerCommandAlias("HUB"); err != nil {
		t.Fatalf("register HUB: %v", err)
	}
	if !p.command.Has("hub") {
		t.Fatal("hub alias should be case-insensitive")
	}
}
