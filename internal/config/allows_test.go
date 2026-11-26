package config

import "testing"

// Invariant 22 at the matcher: unset, the issuer and nothing else; set, the
// list and nothing else, the issuer not added implicitly; never an empty
// audience, even against a config whose issuer is empty.
func TestAllowsAudienceIsTheIssuerAloneOrTheListAlone(t *testing.T) {
	const iss = "https://vouchryx.acme.example"
	unset := Config{Issuer: iss}
	for aud, want := range map[string]bool{
		iss: true, iss + "/": false, "https://api.acme.example": false, "": false,
	} {
		if got := unset.AllowsAudience(aud); got != want {
			t.Errorf("unset list: AllowsAudience(%q) = %v, want %v", aud, got, want)
		}
	}
	if (Config{}).AllowsAudience("") {
		t.Error("an empty audience was allowed by a config with an empty issuer")
	}
	listed := Config{Issuer: iss, AllowedAudiences: []string{"https://api.acme.example"}}
	for aud, want := range map[string]bool{
		"https://api.acme.example": true, "https://api.acme.example.evil.test": false, iss: false, "": false,
	} {
		if got := listed.AllowsAudience(aud); got != want {
			t.Errorf("listed: AllowsAudience(%q) = %v, want %v", aud, got, want)
		}
	}
}
