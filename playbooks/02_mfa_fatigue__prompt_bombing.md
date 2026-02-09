# Playbook 02: MFA Fatigue (Prompt Bombing)

## One-page Summary
Confirm prompt storm, block IP, reset MFA, revoke tokens, investigate sign-ins and mailbox rules.

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
