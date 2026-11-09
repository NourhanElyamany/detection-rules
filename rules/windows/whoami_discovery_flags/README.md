# Whoami Execution With Discovery Flags

| Field | Value |
|---|---|
| Rule file | `whoami_discovery_flags.yml` |
| Sigma ID | `9e940be7-f2f5-4f1f-bbcc-9fe0926ede95` |
| ATT&CK technique | `T1033` System Owner/User Discovery |
| ATT&CK tactic | Discovery |
| Log source | windows / process_creation |
| Status | experimental |
| Level | medium |

## What it detects

Detects `whoami.exe` run with `/all`, `/priv` or `/groups`, including renamed copies of the binary and alternative dash characters (`-all`, `/all` and Unicode dash lookalikes).

## Why it matters

After initial access, attackers run whoami to learn which account they control, which groups it belongs to and which privileges it holds (for example `SeDebugPrivilege` or `SeImpersonatePrivilege`). The answer decides their next step: privilege escalation, credential dumping or lateral movement. Plain `whoami` is common and noisy, but these flags ask for much more detail and are rarer in normal use.

Source: https://attack.mitre.org/techniques/T1033/

## Detection logic

- `selection_img` matches the process by `Image` ending in `\whoami.exe` OR by `OriginalFileName` equal to `whoami.exe`. The second field catches a renamed copy, because the original name is stored inside the binary and does not change when the file is renamed.
- `selection_cli` matches the command line containing ` -all`, ` -priv` or ` -groups`. The `windash` modifier expands each value to `-`, `/` and Unicode dash variants, since Windows accepts several and attackers use them to dodge simple string matches. The leading space keeps the match on a separate argument.
- `condition: all of selection_*` requires both, so plain `whoami` with no flags does not fire.

Note: `OriginalFileName` is a Sysmon field. With Security event 4688 only, the rename detection does not work, and `CommandLine` needs command-line process auditing enabled.

## Known false positives

- Administrators troubleshooting permissions or group membership. Tune by filtering known admin accounts (`User`) or by limiting the alert to non-admin workstations.
- IT inventory, login or deployment scripts that collect user context. Tune by filtering the known parent process (`ParentImage`) or the service account that runs the script.

## How I tested it

- Lab setup: not built yet (planned for Module 3).
- Attack simulation: planned with Atomic Red Team T1033.
- True positive result: not yet tested against lab data.
- Benign check: not yet tested.
- `sigma check` result: pass, 0 errors and 0 issues (sigma-cli 4.0.0). Splunk conversion reviewed with `sigma convert -t splunk -p splunk_windows`.

## References

- https://attack.mitre.org/techniques/T1033/
- Based on SigmaHQ rule `proc_creation_win_whoami_all_execution.yml`: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_whoami_all_execution.yml
