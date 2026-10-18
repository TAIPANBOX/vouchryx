package api

// Scaffold for invariants 23 to 25: the names the tests use, and today's
// behaviour (the grant does not exist, so it answers unsupported_grant_type).

// ClientCredentialsGrantType is RFC 6749 section 4.4's grant.
const ClientCredentialsGrantType = "client_credentials"

// AgentTokenTyp is the JWS header typ of an agent's own access token (RFC 9068).
const AgentTokenTyp = "at+jwt"

// ClientAssertionJWTBearer is RFC 7523 section 2.2's client assertion type.
const ClientAssertionJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
