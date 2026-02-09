# Playbook 13: External Mail Forwarding Rule

## One-page Summary
Disable rule; reset password; revoke tokens; remove other rules/OAuth grants; restrict external forwarding.

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
