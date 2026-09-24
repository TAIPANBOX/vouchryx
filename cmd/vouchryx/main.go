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
//	VOUCHRYX_ADDR             where to listen (default 127.0.0.1:4310)
//	VOUCHRYX_ISSUER           the `iss` this service puts on every token
//	VOUCHRYX_SIGNING_KEY      PEM EC private key; ES256 is what it issues
//	VOUCHRYX_TRUSTED_ISSUERS  `iss|aud|jwks-path` per line
//	VOUCHRYX_TTL_SECONDS      default 300, capped at one hour
//	VOUCHRYX_EVENTS_PATH      agent-event NDJSON, optional
//	VOUCHRYX_REVOCATIONS_PATH where revocations are kept across a restart, optional
//	VOUCHRYX_CLIENTS          Cross App Access client table, optional; unset closes the grant
//	VOUCHRYX_RESOURCES        Cross App Access resources, required once VOUCHRYX_CLIENTS is set
//	VOUCHRYX_XAA_REQUIRE_DPOP "true" or "false" (default), optional
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/vouchryx/internal/api"
	"github.com/TAIPANBOX/vouchryx/internal/config"
	"github.com/TAIPANBOX/vouchryx/internal/revoke"
	"github.com/TAIPANBOX/vouchryx/internal/xaa"
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

	revs := revoke.New()
	srv := &api.Server{
		Cfg:    cfg,
		Revs:   revs,
		Proofs: delegation.NewVerifier(),
		// Wired unconditionally, whether or not VOUCHRYX_CLIENTS is set: the
		// jwt-bearer grant is closed by Cfg.XAAClients being nil regardless,
		// and Server.Replay is assumed non-nil by construction, the same
		// convention Revs and Proofs already follow.
		Replay: xaa.NewReplayCache(),
		Now:    time.Now,
	}
	if cfg.RevocationsPath != "" {
		st, got, err := revoke.OpenStore(cfg.RevocationsPath, time.Now())
		if err != nil {
			fmt.Fprintf(os.Stderr, "vouchryx: refusing to start: %v\n", err)
			os.Exit(2)
		}
		for _, e := range got.Active {
			if err := revs.Add(e); err != nil {
				fmt.Fprintf(os.Stderr, "vouchryx: refusing to start: restoring %s: %v\n", cfg.RevocationsPath, err)
				os.Exit(2)
			}
		}
		if got.TornTail {
			log.Printf("vouchryx: discarded a half-written last revocation in %s; no caller was told it was durable",
				cfg.RevocationsPath)
		}
		log.Printf("vouchryx: restored %d active revocation(s) from %s, dropped %d expired",
			len(got.Active), cfg.RevocationsPath, got.Expired)
		defer func() { _ = st.Close() }()
		// Assigned only here, where st is known non-nil: a nil *revoke.Store in
		// the interface field would make `s.Store != nil` true and the first
		// revocation would panic.
		srv.Store = st
	} else {
		log.Printf("vouchryx: VOUCHRYX_REVOCATIONS_PATH is unset, so a restart forgets every revocation " +
			"and a revoked token that has not expired works again")
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

	if cfg.XAAClients != nil {
		log.Printf("vouchryx: Cross App Access is open: %d resource(s) configured, DPoP required: %v",
			len(cfg.XAAResources), cfg.XAARequireDPoP)
	} else {
		log.Printf("vouchryx: VOUCHRYX_CLIENTS is unset, so the jwt-bearer grant (Cross App Access) " +
			"answers unauthorized_client to every call")
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
		// A caller that trickles bytes, or never sends the last one, must not
		// tie up a connection here forever: this service already caps every
		// body at 64KiB, and a slow sender is the same denial by another
		// route if nothing bounds how long it may take.
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
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
