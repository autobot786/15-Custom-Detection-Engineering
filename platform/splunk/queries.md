# Splunk Detection Queries (SPL)

Adjust `index`, `sourcetype`, and field names to match your environment.

## 01) Impossible Travel (Privileged)
```spl
index=auth (sourcetype=azuread:signin OR sourcetype=vpn:auth OR sourcetype=okta:system)
user_role IN ("Admin","Global Administrator","Privileged Role Administrator")
| sort 0 user _time
| streamstats current=f last(_time) as prev_time last(country) as prev_country last(src_ip) as prev_ip by user
| eval delta=_time-prev_time
| where delta>0 AND delta<3600 AND country!=prev_country
```

## 02) MFA Fatigue (fails then success)
```spl
(index=auth sourcetype=azuread:signin) action="mfa_challenge" outcome IN ("fail","denied")
| stats count as mfa_fails by user, src_ip
| where mfa_fails>=5
| join user src_ip [ search index=auth sourcetype=azuread:signin action="login" outcome="success" earliest=-15m ]
```

## 03) PowerShell Encoded
```spl
index=endpoint (sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1)
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
(CommandLine="*-enc *" OR CommandLine="*-encodedcommand *" OR CommandLine="*FromBase64String*")
```

## 04) Service Account Interactive Login
```spl
index=auth sourcetype=WinEventLog:Security EventCode=4624
(Account_Name="svc_*" OR Account_Name="service_*" OR Account_Name="*_svc")
(Logon_Type IN (2,10))
```

## 05) Privileged Role Assignment Outside Window
```spl
index=cloud (sourcetype=azure:audit OR sourcetype=o365:management OR sourcetype=okta:system)
(Operation IN ("RoleAssignmentCreated","Add member to role","AddUserToGroup") OR action IN ("RoleAssignmentCreated","AddUserToGroup"))
(GroupName="*Admins*" OR GroupName="*Privileged*" OR TargetGroup="*Admins*" OR TargetGroup="*Privileged*")
| eval hour=strftime(_time,"%H")
| where hour<6 OR hour>20
```

## 06) Scheduled Task with Suspicious Flags
```spl
index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
Image="*\\schtasks.exe" CommandLine="*/create*"
(CommandLine="*/ru SYSTEM*" OR CommandLine="*/rl HIGHEST*" OR CommandLine="*\\Microsoft\\Windows\\*")
```

## 07) Ransomware Behavior (delete surge)
```spl
index=endpoint (sourcetype=edr:file OR sourcetype=sysmon:file)
(file_action IN ("delete","remove") OR Action IN ("delete","remove"))
| bucket _time span=10m
| stats count as deletions values(process_name) as processes by host user _time
| where deletions>200
```

## 08) Cloud Storage Exfil Spike
```spl
index=proxy url_domain IN ("drive.google.com","dropbox.com","box.com","onedrive.live.com","mega.nz")
| bucket _time span=15m
| stats sum(bytes_out) as upload_bytes by user src_ip url_domain _time
| where upload_bytes>500000000
```

## 09) Security Tool Tampering
```spl
index=endpoint (sourcetype=WinEventLog:System OR sourcetype=edr:service)
(service_action IN ("stop","disable") OR EventCode IN (7036,7040))
(service_name IN ("WinDefend","Sense","WdNisSvc","Sysmon","CrowdStrike","CarbonBlack") OR ServiceName IN ("WinDefend","Sense","WdNisSvc"))
```

## 10) SMB Lateral Movement Burst
```spl
index=network (dest_port=445 OR app="smb" OR protocol="smb")
| bucket _time span=10m
| stats dc(dest_ip) as targets values(dest_ip) as target_list by src_ip user _time
| where targets>=10
```

## 11) New Admin Created Quickly
```spl
index=auth sourcetype=WinEventLog:Security (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| transaction Account_Name maxspan=30m
| search (EventCode=4720) AND (EventCode=4728 OR EventCode=4732) Group_Name IN ("Domain Admins","Administrators")
```

## 12) DNS to Newly Registered Domains (enriched)
```spl
index=dns domain_age_days<=30
| stats count by src_ip user query domain_age_days
```

## 13) External Mail Forwarding Rule
```spl
index=o365 Operation IN ("New-InboxRule","Set-InboxRule")
| eval forward_to=coalesce(ForwardTo, ForwardingAddress, RecipientToForward)
| where like(forward_to,"%@%") AND NOT like(forward_to,"%<YOUR_COMPANY_DOMAIN>")
```

## 14) VPN Login from Non-Compliant Device
```spl
index=vpn action="vpn_login" outcome="success"
| where device_compliant="false" OR device_posture="noncompliant"
```

## 15) Dormant User Sensitive Access Spike (enriched)
```spl
index=file data_classification IN ("Sensitive","Confidential","PII") last_seen_days>=30
| bucket _time span=15m
| stats count as accesses dc(file_path) as unique_files by user host _time
| where accesses>200 OR unique_files>100
```
