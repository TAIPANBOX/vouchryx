// Command vouchryx issues short-lived, sender-constrained delegation tokens.
//
// It is the mechanism agent-passport SPEC section 2 points at and deliberately
// does not provide: the Passport NAMES an agent and records who acted on whose
// behalf; it does not prove possession and carries no freshness. RFC 8693 token
// exchange with nested `act`, sender-constrained by RFC 9449 DPoP, is that
// proof. Nothing here replaces `on_behalf_of`; this is what makes it provable.
//
// Configuration, all required except the first:
//
//	VOUCHRYX_ADDR             where to listen (default 127.0.0.1:4300)
//	VOUCHRYX_ISSUER           the `iss` this service puts on every token
//	VOUCHRYX_SIGNING_KEY      PEM EC private key; ES256 is what it issues
//	VOUCHRYX_TRUSTED_ISSUERS  `iss|aud|jwks-path` per line
//	VOUCHRYX_TTL_SECONDS      default 300, capped at one hour
//	VOUCHRYX_EVENTS_PATH      agent-event NDJSON, optional
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/vouchryx/internal/api"
	"github.com/TAIPANBOX/vouchryx/internal/config"
	"github.com/TAIPANBOX/vouchryx/internal/dpop"
	"github.com/TAIPANBOX/vouchryx/internal/revoke"
)

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		// Refusing to start beats starting wrong. A token service that came up
		// trusting nothing would issue nothing and look healthy; one that came
		// up trusting a default would issue everything.
		fmt.Fprintf(os.Stderr, "vouchryx: refusing to start: %v\n", err)
		os.Exit(2)
	}

	srv := &api.Server{
		Cfg:    cfg,
		Revs:   revoke.New(),
		Proofs: dpop.NewVerifier(),
		Now:    time.Now,
	}
	if cfg.EventsPath != "" {
		w, err := event.NewWriter(cfg.EventsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "vouchryx: refusing to start: events path %s: %v\n", cfg.EventsPath, err)
			os.Exit(2)
		}
		defer func() { _ = w.Close() }()
		srv.Events = w
	} else {
		log.Printf("vouchryx: VOUCHRYX_EVENTS_PATH is unset, so no delegation is recorded on the bus")
	}

	if warn := bindWarning(cfg.Addr); warn != "" {
		log.Printf("vouchryx: %s", warn)
	}
	log.Printf("vouchryx: listening on %s, issuing as %s, trusting %d issuer(s), ttl %v",
		cfg.Addr, cfg.Issuer, len(cfg.Trusted), cfg.TTL)

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("vouchryx: %v", err)
	}
}

// bindWarning says something when this binds somewhere the whole network can
// reach. It does not refuse: a deployment behind an ingress binds 0.0.0.0 on
// purpose, and a service that refused would be one an operator works around by
// disabling the check. What it must not do is stay silent, which is how the MCP
// broker's own default bind went unexamined until 2026-08-05.
func bindWarning(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return "listening on every interface. This service mints delegation tokens; " +
			"put it behind something that authenticates, or bind it to loopback"
	}
	if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
		return "listening on a routable address. This service mints delegation tokens; " +
			"put it behind something that authenticates"
	}
	return ""
}
