# SIEM / SOAR Scaffolding Pack (Sentinel + Splunk SOAR + Elastic)

This pack provides **near-ready scaffolding** to operationalize the Custom Detection Engineering rules:

- **Microsoft Sentinel**: Logic App playbook action list + workflow definition template + webhook payload examples
- **Splunk SOAR (Phantom)**: Python playbook scaffold + metadata + payload examples
- **Elastic Security**: Rule actions examples + NDJSON-style rule snippets + webhook payload templates

## Important
- Replace placeholders (`<...>`) with your environment values.
- Validate permissions and approvals before enabling automated containment.
- Use the payload examples to test webhooks and ingestion safely.

## Folders
- `sentinel_logic_app/`
- `splunk_soar/`
- `elastic_actions/`
