# Playbook 10: SMB Lateral Movement Burst

## One-page Summary
Confirm management tooling vs attacker; isolate source; reset creds; segment SMB; hunt for remote exec.

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
