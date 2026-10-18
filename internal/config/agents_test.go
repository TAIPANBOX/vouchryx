package config

import (
	"strings"
	"testing"
)

// VOUCHRYX_AGENTS and VOUCHRYX_WORKLOAD_ISSUERS (invariant 23): who this
// service issues an agent's own credential to, and which cluster it believes
// about a workload. Both are statements about who to believe, so a malformed
// value refuses the start like every other one here (invariant 8).

const k8sIssuer = "https://k3s.acme.example"

func agentsEnv(t *testing.T) map[string]string {
	t.Helper()
	env := baseXAAEnv(t)
	env["VOUCHRYX_AGENTS"] = strings.Join([]string{
		"agent://acme.example/agents/triage|agents|default|" + testDigest("triage-key-0123456789"),
		"agent://acme.example/agents/k8s-worker|agents|default|workload:" + k8sIssuer + "#system:serviceaccount:agents:triage",
	}, "\n")
	env["VOUCHRYX_WORKLOAD_ISSUERS"] = k8sIssuer + "|https://vouchryx.acme.example|" + jwksFile(t, "sa-key-1")
	return env
}

func TestAWellFormedAgentsAndWorkloadIssuersConfigComesUp(t *testing.T) {
	withEnv(t, agentsEnv(t), func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatalf("a well-formed agents config was refused: %v", err)
		}
		if c.Agents == nil || c.Agents.Len() != 2 {
			t.Fatalf("the registry did not load: %+v", c.Agents)
		}
		w, ok := c.FindWorkloadIssuer(k8sIssuer)
		if !ok || w.Audience != "https://vouchryx.acme.example" || len(w.Keys.Keys) != 1 {
			t.Fatalf("the workload issuer did not load: %+v %v", w, ok)
		}
		// A workload issuer is not a trusted issuer: its tokens are a
		// credential to this service, never a subject or actor to exchange.
		if _, ok := c.FindIssuer(k8sIssuer); ok {
			t.Fatal("a workload issuer became a trusted issuer for the exchange grant")
		}
	})
}

func TestWithNoAgentsConfiguredTheRegistryIsNil(t *testing.T) {
	withEnv(t, baseXAAEnv(t), func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if c.Agents != nil {
			t.Fatal("VOUCHRYX_AGENTS was unset and a registry exists")
		}
	})
	// And the same environment with agents set does load one: the control
	// that makes "nil" above a fact about the variable, not about the code.
	withEnv(t, agentsEnv(t), func() {
		c, err := FromEnv()
		if err != nil || c.Agents == nil {
			t.Fatalf("control: VOUCHRYX_AGENTS set and no registry: %v", err)
		}
	})
}

func TestAMalformedAgentsLineRefusesToStart(t *testing.T) {
	env := agentsEnv(t)
	env["VOUCHRYX_AGENTS"] = "agent://acme.example/agents/triage|agents|default|sha256:short"
	withEnv(t, env, func() {
		err := mustFail(t)
		if !strings.Contains(err.Error(), "VOUCHRYX_AGENTS") {
			t.Fatalf("the error does not name the variable: %v", err)
		}
	})
	withEnv(t, agentsEnv(t), func() {
		if _, err := FromEnv(); err != nil {
			t.Fatalf("control: the good table was refused: %v", err)
		}
	})
}

func TestAnAgentBoundToAnUnconfiguredWorkloadIssuerRefusesToStart(t *testing.T) {
	env := agentsEnv(t)
	delete(env, "VOUCHRYX_WORKLOAD_ISSUERS")
	t.Setenv("VOUCHRYX_WORKLOAD_ISSUERS", "")
	withEnv(t, env, func() {
		err := mustFail(t)
		if !strings.Contains(err.Error(), k8sIssuer) || !strings.Contains(err.Error(), "VOUCHRYX_WORKLOAD_ISSUERS") {
			t.Fatalf("the error does not name the issuer and the variable that fixes it: %v", err)
		}
	})
	withEnv(t, agentsEnv(t), func() {
		if _, err := FromEnv(); err != nil {
			t.Fatalf("control: with the issuer configured it was refused: %v", err)
		}
	})
}

func TestAWorkloadIssuerWithAnEmptyAudienceIsRefused(t *testing.T) {
	env := agentsEnv(t)
	env["VOUCHRYX_WORKLOAD_ISSUERS"] = k8sIssuer + "||" + jwksFile(t, "sa-key-1")
	withEnv(t, env, func() {
		err := mustFail(t)
		if !strings.Contains(err.Error(), k8sIssuer) || !strings.Contains(err.Error(), "VOUCHRYX_WORKLOAD_ISSUERS") {
			t.Fatalf("the error names neither the issuer nor the variable: %v", err)
		}
	})
	withEnv(t, agentsEnv(t), func() {
		if _, err := FromEnv(); err != nil {
			t.Fatalf("control: refused with an audience present: %v", err)
		}
	})
}

// VOUCHRYX_TRUSTED_ISSUERS is required unless this service issues agents
// their own credential: a deployment of agents with no human identity
// provider has nobody to trust for the exchange grant, and making it invent
// one would make it configure a trust it does not want.
func TestTrustedIssuersAreOptionalOnlyWhenAgentsAreConfigured(t *testing.T) {
	env := agentsEnv(t)
	env["VOUCHRYX_TRUSTED_ISSUERS"] = ""
	withEnv(t, env, func() {
		c, err := FromEnv()
		if err != nil {
			t.Fatalf("an agents-only service was refused: %v", err)
		}
		if len(c.Trusted) != 0 {
			t.Fatalf("trusted issuers appeared from nowhere: %v", c.Trusted)
		}
	})
	plain := baseXAAEnv(t)
	plain["VOUCHRYX_TRUSTED_ISSUERS"] = ""
	withEnv(t, plain, func() {
		err := mustFail(t)
		if !strings.Contains(err.Error(), "VOUCHRYX_TRUSTED_ISSUERS") {
			t.Fatalf("without agents the variable is still required, and the error must name it: %v", err)
		}
	})
}
