// Command vouchryx-demo mints the credentials a caller needs in order to walk
// the loop this service exists for: exchange, spend, revoke, refused.
//
// It is a CLIENT. It verifies nothing and decides nothing, and every check
// stays at the far end: a wrong credential minted here is refused there. See
// internal/demo for why that is the only shape in which a minting helper is
// safe to ship beside a service that refuses for a living.
//
// It is defensive tooling, for exercising and then ending your own agents'
// authority.
//
//	vouchryx-demo keygen   -out idp
//	vouchryx-demo exchange -url http://127.0.0.1:4310 ...
//	vouchryx-demo proof    -key holder.pem -htm POST -htu http://127.0.0.1:4100/v1/messages
//
// The holder key is the point of the third one. A delegation token is bound to
// the key whose proof was presented at the exchange, so the SAME key has to
// sign a fresh proof for every request the token is then spent on.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
	"github.com/TAIPANBOX/vouchryx/internal/demo"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "exchange":
		err = exchange(os.Args[2:])
	case "proof":
		err = proof(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vouchryx-demo: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `vouchryx-demo mints what a caller of this service needs.

  keygen   -out <prefix> [-kid <kid>]
      Writes <prefix>.pem (private, mode 600) and <prefix>.jwks.json (public).
      The JWKS is what VOUCHRYX_TRUSTED_ISSUERS and TOKENFUSE_DELEGATION_JWKS
      take.

  exchange -url <vouchryx-origin> -idp-key <pem> -kid <kid>
           -iss <issuer> -aud <audience>
           -subject <user://...> -actor <agent://...> -holder-key <pem>
      Mints the two input tokens a customer's own IdP would have issued, mints
      a DPoP proof with the holder key, performs the RFC 8693 exchange and
      prints the delegation token.

  proof    -key <pem> -htm <method> -htu <absolute-url> [-jti <id>]
      One DPoP proof, bound to one method and one destination. A token is
      bound to the key that proved possession at the exchange, so this must be
      the same key, and a fresh proof is needed per request.
`)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "path prefix for <prefix>.pem and <prefix>.jwks.json")
	kid := fs.String("kid", "", "key id for the published set (default: the key's RFC 7638 thumbprint)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*out) == "" {
		return fmt.Errorf("-out is required")
	}
	key, err := demo.GenerateKey()
	if err != nil {
		return err
	}
	name := *kid
	if strings.TrimSpace(name) == "" {
		// The thumbprint is a defensible default: it is derived from the key,
		// so two keys never collide and a rotation never reuses a name.
		if name, err = delegation.Thumbprint(delegation.FromPublic(&key.PublicKey, "")); err != nil {
			return err
		}
	}
	if err := demo.WriteKey(*out+".pem", key); err != nil {
		return err
	}
	if err := demo.WriteJWKS(*out+".jwks.json", &key.PublicKey, name); err != nil {
		return err
	}
	fmt.Printf("%s.pem\t\tprivate, mode 600\n%s.jwks.json\tpublic, kid %s\n", *out, *out, name)
	return nil
}

func exchange(args []string) error {
	fs := flag.NewFlagSet("exchange", flag.ContinueOnError)
	url := fs.String("url", "", "the vouchryx origin, e.g. http://127.0.0.1:4310")
	idpKey := fs.String("idp-key", "", "PEM EC private key of the issuer this service trusts")
	kid := fs.String("kid", "", "the kid naming that key in the trusted JWKS")
	iss := fs.String("iss", "", "the issuer's `iss`, matching VOUCHRYX_TRUSTED_ISSUERS")
	aud := fs.String("aud", "", "the audience, matching VOUCHRYX_TRUSTED_ISSUERS")
	subject := fs.String("subject", "", "who the work is done for, e.g. user://acme/ada")
	actor := fs.String("actor", "", "who will act, e.g. agent://acme/triage")
	holderKey := fs.String("holder-key", "", "PEM EC private key the token will be bound to")
	ttl := fs.Duration("input-ttl", time.Hour, "how long the minted input tokens live")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, v := range map[string]string{
		"-url": *url, "-idp-key": *idpKey, "-kid": *kid, "-iss": *iss,
		"-aud": *aud, "-subject": *subject, "-actor": *actor, "-holder-key": *holderKey,
	} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}

	idp, err := demo.ReadKey(*idpKey)
	if err != nil {
		return err
	}
	holder, err := demo.ReadKey(*holderKey)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	endpoint := strings.TrimRight(*url, "/") + "/v1/token"
	sub, err := demo.InputToken(idp, *kid, *iss, *aud, *subject, now, *ttl)
	if err != nil {
		return err
	}
	act, err := demo.InputToken(idp, *kid, *iss, *aud, *actor, now, *ttl)
	if err != nil {
		return err
	}
	// The jti is per-proof and a server may refuse a repeat, so it is derived
	// from the moment rather than fixed.
	p, err := demo.Proof(holder, "POST", endpoint, fmt.Sprintf("demo-%d", now.UnixNano()), now)
	if err != nil {
		return err
	}
	tok, err := demo.Exchange(context.Background(), http.DefaultClient, endpoint, sub, act, p)
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func proof(args []string) error {
	fs := flag.NewFlagSet("proof", flag.ContinueOnError)
	keyPath := fs.String("key", "", "PEM EC private key, the one the token is bound to")
	htm := fs.String("htm", "POST", "the HTTP method this proof is for")
	htu := fs.String("htu", "", "the absolute URL this proof is for")
	jti := fs.String("jti", "", "proof id (default: derived from the moment)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*keyPath) == "" || strings.TrimSpace(*htu) == "" {
		return fmt.Errorf("-key and -htu are required")
	}
	key, err := demo.ReadKey(*keyPath)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	id := *jti
	if strings.TrimSpace(id) == "" {
		id = fmt.Sprintf("demo-%d", now.UnixNano())
	}
	p, err := demo.Proof(key, *htm, *htu, id, now)
	if err != nil {
		return err
	}
	fmt.Println(p)
	return nil
}
