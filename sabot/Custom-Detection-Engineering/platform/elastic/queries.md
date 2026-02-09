# Elastic Queries (KQL + EQL concepts)

Adjust index patterns and field names to match ECS mappings.

## 01) Impossible Travel (KQL + correlation hint)
```text
event.category:authentication AND user.roles:(Admin OR "Global Administrator" OR "Privileged Role Administrator")
```
Correlation: compare geo.country_iso_code changes within 1h per user.name.

## 02) MFA Fatigue (KQL + threshold hint)
```text
event.category:authentication AND event.action:mfa_challenge AND event.outcome:(failure OR denied)
```
Threshold: >=5 failures per user.name + source.ip in 15m, then event.outcome:success.

## 03) PowerShell Encoded
```text
process.name:(powershell.exe OR pwsh.exe) AND
(process.command_line:*"-enc"* OR process.command_line:*"-encodedcommand"* OR process.command_line:*"FromBase64String"*)
```

## 04) Service Account Interactive Login
```text
event.category:authentication AND winlog.event_id:4624 AND
(user.name:svc_* OR user.name:service_* OR user.name:*_svc) AND
winlog.event_data.LogonType:(2 OR 10)
```

## 05) Privileged Role Assignment Outside Window
```text
event.category:iam AND event.action:(RoleAssignmentCreated OR "Add member to role" OR AddUserToGroup) AND
(group.name:*Admins* OR group.name:*Privileged*)
```

## 06) Scheduled Task Suspicious
```text
process.name:schtasks.exe AND process.command_line:*"/create"* AND
(process.command_line:*"/ru SYSTEM"* OR process.command_line:*"/rl HIGHEST"* OR process.command_line:*"\\Microsoft\\Windows\\"*)
```

## 07) Ransomware Behavior (EQL)
```eql
sequence by host.name, user.name with maxspan=10m
  [ file where event.action in ("deletion","delete") ]
  [ file where event.action in ("rename","move") and file.extension in ("locked","encrypted","enc","crypt") ]
```

## 08) Cloud Storage Exfil Spike
```text
event.category:network AND url.domain:(drive.google.com OR dropbox.com OR box.com OR onedrive.live.com OR mega.nz)
```

## 09) Security Tool Tampering
```text
event.category:service AND event.action:(stop OR disable) AND
service.name:(WinDefend OR Sense OR WdNisSvc OR Sysmon OR CrowdStrike OR CarbonBlack)
```

## 10) SMB Lateral Movement Burst
```text
event.category:network AND destination.port:445
```

## 11) New Admin Created Quickly (EQL)
```eql
sequence with maxspan=30m
  [ iam where event.action in ("user_created","NewUser") ]
  [ iam where event.action in ("add_to_group","AddMember") and group.name in ("Domain Admins","Administrators") ]
```

## 12) DNS to Newly Registered Domains (enriched)
```text
event.category:dns AND threat.enrichment.domain_age_days <= 30
```

## 13) External Mail Forwarding Rule
```text
event.category:email AND event.action:(New-InboxRule OR Set-InboxRule OR CreateForwardingRule) AND
email.forward_to:*@* AND NOT email.forward_to:*<YOUR_COMPANY_DOMAIN>
```

## 14) VPN from Non-Compliant Device
```text
event.category:vpn AND event.action:vpn_login AND event.outcome:success AND device.compliant:false
```

## 15) Dormant User Sensitive Access Spike (enriched)
```text
event.category:file AND data.classification:(Sensitive OR Confidential OR PII) AND user.last_seen_days >= 30
```
