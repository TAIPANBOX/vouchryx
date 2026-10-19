package main

import (
	"context"
	"log"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/agent-stack-go/v2/keyclient"
	"github.com/TAIPANBOX/vouchryx/internal/config"
	"github.com/TAIPANBOX/vouchryx/internal/signer"
)

// buildSigner returns the signer this process signs with. In file mode it is the
// key file, as it always was. In keyryx mode it is a working key Keyryx certifies,
// renewed for as long as the process runs. Until the first certification it signs
// nothing, and health says so (CLAUDE.md invariant 27).
func buildSigner(cfg config.Config) (signer.Signer, error) {
	if cfg.Signer != "keyryx" {
		return signer.NewFile(cfg.SigningKey, cfg.KeyID)
	}
	kc, err := keyclient.New(keyclient.Config{
		BaseURL:    cfg.Keyryx.BaseURL,
		Consumer:   cfg.Keyryx.Consumer,
		Credential: keyclient.Credential{Socket: cfg.Keyryx.Socket, BearerFile: cfg.Keyryx.BearerFile},
	})
	if err != nil {
		return nil, err
	}
	d, err := kc.Delegated(signer.KeyName, "ES256", signer.Lifetime)
	if err != nil {
		return nil, err
	}
	j, err := kc.JWKS(signer.KeyName)
	if err != nil {
		return nil, err
	}
	// During the migration the file key's public half is still served, so
	// verifiers that have it keep verifying. It is never a signer in this mode.
	var overlap *delegation.JWK
	if cfg.SigningKey != nil {
		k := delegation.FromPublic(&cfg.SigningKey.PublicKey, cfg.KeyID)
		overlap = &k
	}
	signer.StartDelegated(context.Background(), d, j, func(err error) {
		log.Printf("vouchryx: signer: %v", err)
	})
	log.Printf("vouchryx: signing with a working key Keyryx certifies (key %s, consumer %s, %s); no token is issued until the first certification",
		signer.KeyName, cfg.Keyryx.Consumer, cfg.Keyryx.BaseURL)
	return signer.NewDelegated(d, j, overlap, time.Now), nil
}
