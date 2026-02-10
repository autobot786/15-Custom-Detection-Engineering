# Elastic Security Actions (How to wire)

## Typical connectors
- Webhook (SOAR endpoint)
- Email
- Slack / Teams
- Jira / ServiceNow

## Recommended approach
1) Create a **Webhook connector** in Kibana → Stack Management → Connectors.
2) Set alert action frequency (per alert vs summary).
3) Use a webhook payload that includes:
   - rule.name
   - severity
   - timestamp
   - host.name / user.name / source.ip
   - file.hash.sha256 (if present)
   - reason (signal reason)

## Example webhook body (templated)
```json
{
  "source": "elastic-security",
  "rule_name": "{{rule.name}}",
  "severity": "{{context.rule.severity}}",
  "timestamp": "{{date}}",
  "entities": {
    "user": "{{context.alerts.0.user.name}}",
    "host": "{{context.alerts.0.host.name}}",
    "source_ip": "{{context.alerts.0.source.ip}}",
    "sha256": "{{context.alerts.0.file.hash.sha256}}"
  },
  "kibana_url": "{{context.results_link}}"
}
```
