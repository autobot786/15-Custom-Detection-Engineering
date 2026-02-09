# Playbook 08: Cloud Storage Exfiltration Spike

## One-page Summary
Confirm volume and legitimacy; block destination; revoke sessions; investigate endpoint for rogue tools.

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
