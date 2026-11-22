# Local Group Discovery Via Net.EXE

| Field | Value |
|---|---|
| Rule file | `net_localgroup_discovery.yml` |
| Sigma ID | `02379bf2-869d-4c38-91b8-d4e5b18fe156` |
| ATT&CK technique | `T1069.001` Permission Groups Discovery: Local Groups |
| ATT&CK tactic | Discovery |
| Log source | windows / process_creation |
| Status | experimental |
| Level | low |

## What it detects

Detects `net.exe` or `net1.exe` run with `localgroup` to list local groups or their members, for example `net localgroup administrators`. Renamed copies are caught through `OriginalFileName`.

## Why it matters

The attacker learns which accounts are members of privileged local groups such as Administrators. Those accounts become targets: their credentials can be stolen or guessed to gain admin rights on the host, and then used to move to other machines.

Source: https://attack.mitre.org/techniques/T1069/001/

## Detection logic

- `selection_img` matches the process as `net.exe` or `net1.exe`, by `Image` ending in `\net.exe` / `\net1.exe` or by `OriginalFileName`. The leading backslash makes sure the file name is exact, so `dotnet.exe` or `evilnet.exe` do not match.
- `selection_cli` matches ` localgroup` anywhere in the command line.
- `filter_main_net1_child` removes duplicates. Running `net.exe` makes Windows start a child `net1.exe` with the same command line, so one command would raise two alerts. The filter drops the event only when the process is `net1.exe` AND its parent is `net.exe`.
- `condition: all of selection_* and not 1 of filter_main_*`

Why the filter is `main`: the net.exe to net1.exe behaviour is the same on every Windows system, so it does not depend on the environment.

Why it is not a blind spot: both fields must match. If an attacker runs `net1.exe` directly (parent `cmd.exe` or `powershell.exe`), the filter does not apply and the rule still fires.

## Known false positives

- Helpdesk or administrators checking local group membership while troubleshooting access.
- Inventory, audit or RMM tools and login scripts that collect group membership.

Tuning: exclude specific known activity, not whole groups of users. For a known tool, add a `filter_optional_` block matching its exact `ParentImage` path and the service account (`User`) it runs as. Do not exclude all admin or IT users: a stolen admin account is exactly the case this rule should catch.

## How I tested it

- Lab setup: not built yet (planned for Module 3).
- Attack simulation: planned with Atomic Red Team T1069.001.
- True positive result: not yet tested against lab data.
- Benign check: not yet tested.
- `sigma check` result: pass, 0 errors and 0 issues (sigma-cli 4.0.0). Splunk conversion reviewed: the filter becomes `NOT (ParentImage="*\\net.exe" Image="*\\net1.exe")`.

## References

- https://attack.mitre.org/techniques/T1069/001/
