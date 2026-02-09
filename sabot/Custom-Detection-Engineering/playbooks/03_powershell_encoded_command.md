# Playbook 03: PowerShell Encoded Command

## One-page Summary
Capture command line/parent, isolate host, kill process tree, remove persistence, enforce signing/CLM.

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
