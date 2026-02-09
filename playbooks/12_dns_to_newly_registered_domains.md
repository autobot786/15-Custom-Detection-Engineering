# Playbook 12: DNS to Newly Registered Domains

## One-page Summary
Validate domain via threat intel; block if malicious; isolate host if beaconing; maintain allowlist.

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
