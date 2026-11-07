# Rule title

| Field | Value |
|---|---|
| Rule file | `rule_name.yml` |
| Sigma ID | `uuid` |
| ATT&CK technique | `Txxxx.xxx` Technique name |
| ATT&CK tactic | Tactic name |
| Log source | product / category (e.g. windows / process_creation) |
| Status | experimental / test / stable |
| Level | informational / low / medium / high / critical |

## What it detects

One or two sentences on the behaviour this rule catches.

## Why it matters

The attacker goal behind this behaviour. Link the threat report or ATT&CK page it came from.

## Detection logic

Plain-language explanation of the selection and condition, and why each field was chosen.

## Known false positives

- Legitimate tool or admin activity that can trigger it
- How to tune it out (filter field and value)

## How I tested it

- Lab setup: OS, Sysmon config, SIEM
- Attack simulation: e.g. Atomic Red Team test ID and command
- True positive result: query used and what fired
- Benign check: normal activity run and whether it fired
- `sigma check` result: pass / warnings

## References

- https://attack.mitre.org/techniques/Txxxx/
