# CLI Edge Cases

The 22.1 Bug Fix Sprint adds helpers for user-facing CLI errors:

- Missing files should show a short error and hint.
- Invalid JSON should identify the file and approximate location.
- Unsafe paths should be blocked before file access.
- Sample file problems should suggest demo or documentation commands.
- Redaction checks should not print raw secrets.

Use `scanner.error_handling` and `scanner.cli_errors` for new CLI checks.
