# Microsoft Sentinel – Logic App Playbook (Action List + Template)

This folder includes a **ready-to-adapt** Logic App workflow definition that you can import as a Sentinel automation playbook.
It is designed for alerts produced by the Custom Detection Engineering detections.

> You must replace placeholders like `<SUBSCRIPTION_ID>`, `<RESOURCE_GROUP>`, `<WORKSPACE_NAME>`, `<TENANT_ID>`, and connector IDs.

## Action list (recommended sequence)

### 0) Trigger
- **Microsoft Sentinel**: *When a response to a Microsoft Sentinel alert is triggered* (or *When an incident is created*)

### 1) Parse entities
- Extract entities from the incident/alert payload:
  - Account: UPN, AAD Object ID
  - Host: device name, device ID (if available)
  - IP: source IP, geo (optional)
  - File hash: SHA256 (if present)
  - URL/Domain (if present)

### 2) Enrichment
- **Azure AD / Entra**: Get user, risk, and sign-in details
  - Get user details
  - List recent sign-ins (last 24h)
  - Check user risk state (Identity Protection, if licensed)
- **Defender for Endpoint** (optional):
  - Get machine details (risk score, exposure)
  - Get last seen process / file events
- **Threat Intel**:
  - Lookup IP/domain/hash against TI provider (VirusTotal/OTX/Microsoft TI)
- **GeoIP** (optional):
  - Enrich IP with geo

### 3) Decision logic (conditions)
- If **High confidence** (e.g., privileged + impossible travel OR MFA fatigue + risky sign-in):
  - Contain: Revoke sessions / disable account / isolate device
- If **Medium confidence**:
  - Notify only + open ticket + require analyst approval step

### 4) Containment actions (choose based on rule)
- **Revoke user sessions** (Graph API / Azure AD connector)
- **Disable user** (temporary) if admin compromise likely
- **Isolate device** (MDE action) if endpoint malware/ransomware suspected
- **Block IP** (optional; via firewall/WAF connector)

### 5) Case management + notification
- Create a ticket (ServiceNow/Jira)
- Post to Teams/Slack SOC channel with a concise summary
- Add a comment to the Sentinel incident with enrichment results
- Update incident severity/tags (e.g., `CDE:ImpossibleTravel`, `CDE:MFAFatigue`)

## Included files
- `logicapp_workflow_definition.json` – import into Logic Apps (Consumption) and attach to Sentinel playbook.
- `webhook_payload_examples.json` – example entity payloads you can use for testing.
