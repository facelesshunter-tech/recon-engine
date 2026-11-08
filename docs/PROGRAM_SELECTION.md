# Program / target selection (TBHM KB §3)

This is a human-judgment step, not something recon-engine automates —
reproduced here as a reference checklist rather than skipped.

## Platforms named in the deck

Beyond HackerOne/Bugcrowd: Synack, Zerocopter, HackenProof, Detectify,
Defend Iceland, BugBounty.jp, Cobalt, Yogosha, bug.sh, Immunefi,
Intigriti, YesWeHack.

## What to check on a program's scope page before running recon-engine against it

- Is this a VDP (no bounty, but still authorized) or a paid program?
- Does the scope use wildcard/catch-all language? TBHM explicitly warns
  these can be misleading — confirm what's actually intended to be
  in-scope, not just what a wildcard pattern incidentally sweeps in.
- Does the program's rules of engagement/SOW frame success in concrete,
  objective terms (e.g. "access to privileged data," "provable
  disruption of services") rather than a vague checklist? TBHM frames
  this as the sign of a program worth investing deep recon effort in.
- Confirm out-of-scope assets explicitly before running `recon-engine
  scan` with `--bruteforce`/`--permutation`/`--github` against a wide
  target list — those stages actively generate and resolve candidate
  hostnames that may include out-of-scope infrastructure.

This project's earlier program shortlist (built in a separate session
from live program research, not from the PDF) is not reproduced here —
check your own current notes for which programs you prioritized and why.
