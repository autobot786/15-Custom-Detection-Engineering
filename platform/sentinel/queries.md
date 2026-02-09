# Microsoft Sentinel Queries (KQL)

These are starter queries; adjust connectors/tables/fields as needed.

## 01) Impossible Travel (Privileged) - Azure AD
```kql
let timeframe = 1h;
SigninLogs
| where TimeGenerated > ago(24h)
| where tostring(Roles) has_any ("Admin","Global Administrator","Privileged Role Administrator")
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType
| order by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated), PrevUser = prev(UserPrincipalName), PrevLoc = prev(Location)
| where UserPrincipalName == PrevUser and isnotempty(PrevLoc) and isnotempty(Location)
| where TimeGenerated - PrevTime < timeframe and Location != PrevLoc
```

## 02) MFA Fatigue (fails then success)
```kql
let window = 15m;
let fails =
SigninLogs
| where TimeGenerated > ago(window)
| where ResultType != 0
| summarize Failures=count() by UserPrincipalName, IPAddress;
let succ =
SigninLogs
| where TimeGenerated > ago(window)
| where ResultType == 0
| project UserPrincipalName, IPAddress, SuccessTime=TimeGenerated;
fails
| where Failures >= 5
| join kind=inner (succ) on UserPrincipalName, IPAddress
```

## 03) PowerShell Encoded (MDE)
```kql
DeviceProcessEvents
| where TimeGenerated > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-enc","-encodedcommand","FromBase64String")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

## 04) Service Account Interactive Login
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| where Account has_any ("svc_","service_") or Account endswith "_svc"
| where LogonType in (2,10)
| project TimeGenerated, Computer, Account, IpAddress, LogonType
```

## 05) Privileged Role Assignment Outside Window
```kql
AzureActivity
| where TimeGenerated > ago(30d)
| where OperationNameValue has_any ("RoleAssignmentCreated","Add member to role","Add user to group")
| extend Hour = datetime_part("Hour", TimeGenerated)
| where Hour < 6 or Hour > 20
| project TimeGenerated, Caller, OperationNameValue, ActivityStatusValue
```

## 06) Suspicious Scheduled Task
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("/ru SYSTEM","/rl HIGHEST","\Microsoft\Windows\")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

## 07) Ransomware Behavior Indicator
```kql
let window=10m;
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where ActionType in~ ("FileDeleted","FileRenamed")
| summarize Deletes=countif(ActionType =~ "FileDeleted"),
          Renames=countif(ActionType =~ "FileRenamed") by DeviceName, InitiatingProcessAccountName, bin(TimeGenerated, window)
| where Deletes > 200 and Renames > 50
```

## 08) Cloud Storage Exfil Spike (proxy)
```kql
let window=15m;
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where DestinationHostName has_any ("drive.google.com","dropbox.com","box.com","onedrive.live.com","mega.nz")
| summarize UploadBytes=sum(SentBytes) by SourceUserName, SourceIP, DestinationHostName, bin(TimeGenerated, window)
| where UploadBytes > 500000000
```

## 09) Security Tool Tampering
```kql
DeviceEvents
| where TimeGenerated > ago(30d)
| where ActionType has_any ("ServiceStopped","ServiceDisabled","TamperProtection")
| where AdditionalFields has_any ("WinDefend","Sense","WdNisSvc","Sysmon","CrowdStrike","CarbonBlack")
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessAccountName
```

## 10) SMB Lateral Movement Burst
```kql
let window=10m;
DeviceNetworkEvents
| where TimeGenerated > ago(7d)
| where RemotePort == 445
| summarize Targets=dcount(RemoteIP) by DeviceName, InitiatingProcessAccountName, bin(TimeGenerated, window)
| where Targets >= 10
```

## 11) New Admin Created Quickly
```kql
let window=30m;
let newUsers =
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID == 4720
| project CreatedTime=TimeGenerated, TargetAccount=TargetUserName, SubjectAccount=Account;
let addAdmin =
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID in (4728,4732)
| where TargetUserName in~ ("Domain Admins","Administrators")
| project AddedTime=TimeGenerated, MemberName=MemberName, GroupName=TargetUserName, SubjectAccount=Account;
newUsers
| join kind=inner (addAdmin) on $left.TargetAccount == $right.MemberName
| where AddedTime - CreatedTime < window
```

## 12) DNS to Newly Registered Domains (enriched)
```kql
DnsEvents
| where TimeGenerated > ago(30d)
| where DomainAgeDays <= 30
| project TimeGenerated, DeviceName, ClientIP, Name, DomainAgeDays
```

## 13) External Mail Forwarding Rule
```kql
OfficeActivity
| where TimeGenerated > ago(90d)
| where Operation in ("New-InboxRule","Set-InboxRule")
| extend Params=parse_json(Parameters)
| extend ForwardTo=tostring(Params[0].Value)
| where ForwardTo contains "@"
| where not(ForwardTo endswith "<YOUR_COMPANY_DOMAIN>")
| project TimeGenerated, UserId, Operation, ForwardTo, ClientIP
```

## 14) VPN Login from Non-Compliant Device (custom table)
```kql
VpnAuth
| where TimeGenerated > ago(30d)
| where Result == "Success"
| where DeviceCompliant == false
| project TimeGenerated, User, IPAddress, DeviceId, DeviceCompliant
```

## 15) Dormant User Sensitive Access Spike (enriched)
```kql
let window=15m;
FileEvents
| where TimeGenerated > ago(30d)
| where DataClassification in ("Sensitive","Confidential","PII")
| where LastSeenDays >= 30
| summarize Accesses=count(), UniqueFiles=dcount(FilePath) by User, DeviceName, bin(TimeGenerated, window)
| where Accesses > 200 or UniqueFiles > 100
```
