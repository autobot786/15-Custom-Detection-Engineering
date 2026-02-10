# Splunk SOAR (Phantom) – Playbook Scaffolding

This folder contains a **starter playbook** you can import/adapt in Splunk SOAR:
- A Python playbook file with: `on_start`, enrichment, decisions, and containment stubs
- A simple JSON metadata file describing assets and actions
- Example webhook payloads (to test ingestion)

## What you must customize
- Asset names: `microsoft_graph`, `mde`, `firewall`, `servicenow`, `slack`
- Action names may differ by app (e.g., `disable user`, `revoke tokens`, `isolate device`)

## Recommended action flow
1) Extract artifacts (user/ip/host/hash) from the container
2) Enrich:
   - GeoIP / WHOIS
   - AD / Graph user lookup
   - TI lookup
   - Device risk (MDE)
3) Decision: confidence score
4) Contain:
   - disable user OR revoke tokens
   - isolate device
   - block IP
5) Notify + ticket
6) Add notes back to container
