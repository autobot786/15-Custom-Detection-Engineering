# Data Sources

Recommended sources:
- Authentication: Azure AD/Okta/AD (4624/4625), VPN auth
- Endpoint: Sysmon, EDR process/file/network
- Network: Proxy, SMB (445), DNS
- Email: M365 audit/OfficeActivity
- IAM: Role assignments / privileged group changes

Enrichment recommended:
- GeoIP country for IPs
- Domain age (days)
- Dormancy (last_seen_days)
- Data classification tags
