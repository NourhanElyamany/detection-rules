# detection-rules
Sigma detection rules mapped to MITRE ATT&CK, tested in CI.

## Structure

- `rules/windows`, `rules/linux`, `rules/network`: Sigma rules by platform. Each rule has a `.yml` file and a `README.md`.
- `templates/`: template for rule README notes.
- `docs/`: write-ups that turn threat reports into detections.

## Workflow

Every rule is added on its own branch, validated in CI, and merged into `main` through a pull request.
