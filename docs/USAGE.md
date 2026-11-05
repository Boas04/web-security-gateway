# Usage and configuration

[Back to README](../README.md)

All Compose commands below run from `ruang-guard/`. Keep the integrated origin private; do not start the standalone portal on port 8000 while demonstrating protected access.

## First walkthrough

1. Open http://localhost:8090 and create a complaint using fictional information only.
2. Save the generated reference and access key. Both are required to look up the complaint; a reference alone does not grant access. The access key is shown once.
3. Use the portal status page to retrieve the complaint. Try an incorrect access key to confirm that details remain unavailable.
4. Open http://localhost:9000/admin/ and sign in with the generated local password.
5. Choose a time range in the overview and inspect the actual requests, decisions, rule IDs, and response times.

The portal API is documented in [ruang-warga/README.md](../ruang-warga/README.md). Portal illustrative home statistics are fictional; **security dashboard traffic statistics are aggregated from stored events**.

## Dashboard

| Area | Use |
| --- | --- |
| Ringkasan | Request totals, decisions, sparklines, events over time, block reasons, and source pseudonyms. |
| Event keamanan | Search/filter events, inspect details, and paginate dense rows. |
| Daftar blokir | Review temporary blocks, repeat-offense levels, expiry, and explicitly unblock/reset a source. |
| Pengaturan proteksi | Select an allowlisted origin and configure request limits, window, and base penalty. |
| Riwayat pengaturan | Review administrator actions. |
| Notifikasi | Inspect grouped origin/WAF failures and spikes in rejected requests; acknowledge notices. |
| Analisis ML | Approve baseline windows, train candidates, activate models, and review coordinated WAF/ML findings. |

**Diizinkan** means the request passed gateway security checks; it does not guarantee the application operation succeeded. **Ditolak** means WAF, rate limit, or policy denied the request. **Gagal diproses** means a technical failure prevented processing. **Perlu ditinjau** belongs to the ML review workflow, not to technical downtime.

The time ranges are 15 minutes, 1 hour, 24 hours, and 7 days. Search is literal text matching, not a query language. It filters event statistics and the event table. Source identifiers are HMAC pseudonyms, not original IP addresses or a reliable count of individual users. Dashboard polling occurs every five seconds while visible.

## Limits and block expiry

Default public quota: **120 requests / 60 seconds**, with a base penalty of **72 seconds**. New violations after expiry produce 72, 144, 288, 576 seconds, and so on, capped at 3,600 seconds. Offense history resets after 24 hours without another violation. Requests during an active block do not extend it. Expiry clears the corresponding rate counter; manual unblock clears the block, counter, and offense history for that identity.

The initial WAF denial returns 403. Rate-limit denial or an already active block returns 429 with `Retry-After`. Administrator login has a separate namespace, five attempts per minute, and a 300-second initial penalty. WAF/rate-limit escalation does not automatically apply to an administrator's ML response.

The TCP peer identifies the source. Client-supplied `X-Forwarded-For` does not select another identity. Docker/NAT can make multiple clients share a peer and therefore a quota. This is not account-based brute-force protection for arbitrary customer applications.

## Notifications and reports

The monitor checks every 15 seconds. Configure these non-secret values in `.env`:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PUBLIC_ORIGIN` | `http://localhost:8090` | Validated public lab origin. |
| `ALERT_BLOCK_THRESHOLD` | `30` | Rejected requests needed within the window. |
| `ALERT_WINDOW_SECONDS` | `60` | Spike observation window. |
| `ALERT_FAILURE_COUNT` | `2` | Consecutive failed probes before a failure alert. |

After changing `.env`, recreate affected services with `docker compose -p ruang-guard up -d`. Repeated incidents of the same type and target are grouped until recovery. Acknowledgement means an administrator has read the alert, not that the underlying condition recovered. Notifications are local; there is no email or messaging integration.

CSV exports contain event metadata. JSON additionally includes latency summaries, health, incidents, and ML/coordination findings. Event exports follow time and text filters; health/incidents/ML follow time only. A snapshot of current health is not evidence of historical availability. Exports contain no complaint text, tokens, or original client IPs. Review any export before publication.

## Switch to the second fictional application

```sh
docker compose -p ruang-guard --profile demo up -d --build demo-app
```

In **Pengaturan proteksi**, select `katalog-lab` and save. Refresh http://localhost:8090 to see the fictional catalog. Select `ruang-warga` again before stopping the optional application:

```sh
docker compose -p ruang-guard --profile demo stop demo-app
```

Only one origin is active at a time. This demonstrates application separation, not multi-tenant routing.

## Add an allowed local origin

1. Add a service on the Compose `origin` network, with an unused static address in its configured subnet and **no host port**. Leave the existing `.10` and `.20` addresses reserved.
2. Add the address, port, and health path to `config/origins.json`. Example additional entry:

```json
"another-lab": {
  "address": "172.30.10.30",
  "port": 8000,
  "health_path": "/api/health"
}
```

3. Ensure the application accepts `Host: localhost:8090` and compatible same-origin browser requests. Origin validation is not disabled by the gateway.
4. Start the new service, then restart `gateway admin monitor` to reload the allowlist. Select its ID through the authenticated dashboard.
5. Switch away from an active origin before removing its allowlist entry.

The example is an entry inside the existing JSON object, not a complete replacement file. The allowlist accepts explicit RFC1918 IP addresses, not arbitrary domains/URLs, loopback, public, or metadata/link-local destinations. Redirects are not followed. Public domains, HTTPS upstreams, and external customer onboarding require additional design.

## Tune WAF rules

The SecLang configuration and Coraza setup are in `ruang-guard/waf/main.go`; module versions are in `go.mod` and `go.sum`. The default uses CRS blocking at paranoia level 1 with request-body inspection. Response-body inspection is not enabled.

Reproduce a false positive, inspect the specific rule ID, and make any exclusion narrowly scoped to the affected field and route using supported SecLang directives. Do not disable the entire WAF to make a form pass. After changes, run the Go tests and controlled integration tests, then rebuild `waf`. See [testing](TESTING.md) and the [CRS documentation](https://coreruleset.org/docs/).
