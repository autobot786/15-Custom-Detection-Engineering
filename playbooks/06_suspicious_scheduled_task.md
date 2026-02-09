# Playbook 06: Suspicious Scheduled Task

## One-page Summary
Inspect task name/author/action; disable task; isolate if malware; remove payload; hunt across fleet.

## Triage
- Gather key context (user/host/IP/process/time window)
- Check related alerts and recent sign-ins

## Containment
- Apply minimum necessary containment (account/session isolation, host isolation, block indicators)

## Eradication & Recovery
- Remove persistence / reset creds where needed
- Restore systems and verify security controls

## Lessons Learned
- Tune thresholds/allowlists and update baselines
