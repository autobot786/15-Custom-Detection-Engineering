# Playbook 05: Privileged Role Assignment Outside Window

## One-page Summary
Verify ticket/approval; remove role if suspicious; rotate admin creds; enforce PIM/JIT approvals.

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
