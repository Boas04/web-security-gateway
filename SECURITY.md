# Security boundaries and reporting

This project is a fictional, single-host cybersecurity lab. The maintained deployment in this repository publishes only loopback ports. It is not a production security appliance, public hosting service, or promise of comprehensive attack prevention.

## Included protections

- Coraza/OWASP CRS request inspection and fail-closed behavior when inspection fails.
- Transactional rate-limit state and progressive, expiring blocks tied to the TCP peer identity.
- Administrator authentication, session rotation/expiry, CSRF checks, and separate login limiting.
- Explicit origin allowlist, fixed private addresses, redirect restrictions, and strict public Host/Origin validation.
- No trust in arbitrary client forwarding headers.
- Metadata-only security events and HMAC source identifiers.
- Independent application validation, parameterized queries, and complaint access-key checks.
- ML baseline approval, candidate validation, integrity checking, and administrator-reviewed responses.

## Limits

WAF rules and anomaly models can produce false positives and false negatives. They do not fix application authorization flaws or guarantee detection of every SQLi, XSS, traversal, or authentication attack. Rate limiting is not volumetric DDoS mitigation. NAT clients may share a limit. The gateway/database are single-host components without high availability.

The administrator interface uses HTTP only on loopback; cookies are not configured for public HTTPS deployment. Do not expose the dashboard or change published bindings to all interfaces. Customer domains, TLS, MFA, multiple administrators, backups, availability engineering, capacity testing, and operational monitoring require separate work.

No cloud or government environment is connected. Do not use real complaints or personal information. The portal database stores fictional complaint text by design; the security database does not copy that text.

## Before publishing changes or evidence

Keep `.env`, `secrets/`, database files, local models, raw logs, exports, test-results, and personal documents outside commits. `.env.example` contains configuration examples only. Review changes before staging; an ignore file is not proof that every file is safe.

## Reporting a problem

For non-sensitive bugs, open a repository issue with a minimal fictional reproduction, expected/actual behavior, and the relevant commit. Do not attach credentials, session cookies, complaint keys, databases, or real user traffic. For a sensitive vulnerability, use GitHub private vulnerability reporting if the repository offers it; otherwise request a private contact channel without publishing exploit details or secrets. No dedicated response SLA is claimed.
