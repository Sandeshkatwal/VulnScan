"""Local API helpers for program scope files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scanner.bug_bounty_scope import (
    BUG_BOUNTY_SCOPE_DIR,
    PROGRAM_SCOPE_DIR,
    BugBountyScopeError,
    get_scope_decision,
    load_bug_bounty_scope,
    scope_metadata,
)


def list_scope_files(scope_dir: Path | str = BUG_BOUNTY_SCOPE_DIR) -> list[dict[str, Any]]:
    """List valid local scope JSON files under the configured scope directory."""
    scopes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for directory in _scope_directories(scope_dir):
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.json")):
            try:
                scope = load_bug_bounty_scope(path)
            except BugBountyScopeError:
                continue
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            scopes.append(scope_metadata(scope, _display_path(path)))
    return scopes


def get_scope_by_program_id(program_id: str, scope_dir: Path | str = BUG_BOUNTY_SCOPE_DIR) -> dict[str, Any] | None:
    """Return one local scope file by program ID."""
    for summary in list_scope_files(scope_dir):
        if summary.get("program_id") == program_id:
            path = resolve_scope_file(str(summary.get("scope_file") or ""), scope_dir)
            scope = load_bug_bounty_scope(path)
            return {"metadata": scope_metadata(scope, _display_path(path)), "scope": scope}
    return None


def check_scope(target: str, scope_file: str, scope_dir: Path | str = BUG_BOUNTY_SCOPE_DIR) -> dict[str, Any]:
    """Evaluate a target against one local scope file."""
    path = resolve_scope_file(scope_file, scope_dir)
    scope = load_bug_bounty_scope(path)
    return get_scope_decision(target, scope)


def resolve_scope_file(scope_file: str, scope_dir: Path | str = BUG_BOUNTY_SCOPE_DIR) -> Path:
    """Resolve a scope file while preventing reads outside local Program Scope directories."""
    directories = [directory.resolve() for directory in _scope_directories(scope_dir)]
    raw_path = Path(scope_file)
    candidate = raw_path if raw_path.is_absolute() else Path(scope_file)
    if not candidate.is_absolute():
        if len(candidate.parts) >= 2 and candidate.parts[0] == "data" and candidate.parts[1] in {"programs", "bug_bounty"}:
            candidate = Path.cwd() / candidate
        elif len(candidate.parts) > 1:
            raise BugBountyScopeError("Scope file must be a local JSON file under data/programs or legacy data/bug_bounty.")
        else:
            for directory in directories:
                scoped_candidate = directory / candidate.name
                if scoped_candidate.exists():
                    candidate = scoped_candidate
                    break
            else:
                candidate = directories[0] / candidate.name
    resolved = candidate.resolve()
    if not any(_is_relative_to(resolved, directory) for directory in directories):
        raise BugBountyScopeError("Scope file must be a local JSON file under data/programs or legacy data/bug_bounty.")
    if resolved.suffix.lower() != ".json":
        raise BugBountyScopeError("Scope file must be a JSON file.")
    return resolved


def _scope_directories(scope_dir: Path | str = BUG_BOUNTY_SCOPE_DIR) -> list[Path]:
    requested = Path(scope_dir)
    directories = [PROGRAM_SCOPE_DIR, BUG_BOUNTY_SCOPE_DIR]
    if requested not in directories:
        directories.insert(0, requested)
    return directories


def _is_relative_to(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
        return True
    except ValueError:
        return False


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)
