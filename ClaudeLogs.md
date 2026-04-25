# Logging what I'm doing with Claude

## Init

- Ran `/init` reviewed resulting CLAUDE.md file
- Updated it manually to include a section about updating this log for future actions.

## Repo overview

- Explored the full project structure and read all source files to describe the repo to the user.

Result: Helpful — gave a clear summary of the scaffold, tech stack, architecture patterns, and current state of
commands.

## Implemented CycloneDX 1.6 SBOM ingestion with SQLite storage

- Evaluated 5 storage options (SQLite raw, SQLAlchemy, Peewee, JSON files, DuckDB) — chose stdlib sqlite3 for zero
  dependencies.
- Created `src/sbom_cli/db/` module: schema with migration runner, repository for transactional ingestion, dataclass
  models.
- Schema: `bom`, `component`, `license`, `component_license`, `dependency` tables with indexes for name/version and
  license queries.
- Updated `ingest` command to accept a filepath, validate CycloneDX 1.6 JSON, and store to `~/.sbom-cli/sbom.db`.
- Added 16 new tests (repository + CLI integration) — all 21 tests passing, ruff clean.

Result: Helpful — fully working ingestion pipeline from CLI to SQLite, ready for the query command to build on.

> Note - I (Alex) used plan mode and iterated over a few ideas, I also thoroughly reviewed after this change.

## Tidied up db module organization

- Moved `load_and_validate()` from `db/repository.py` to `lib/sbom.py` — it's SBOM parsing, not DB logic.
- Deleted unused `db/models.py` (dataclasses were never imported).
- Updated `ingest.py` to use shared `console` from `lib/output.py` instead of creating its own.
- Moved corresponding tests to match new file locations.

Result: Helpful — cleaner separation of concerns, all 21 tests still passing.

## Implemented query command

- Added `query_components()` and `query_by_license()` to `db/repository.py` — pure SQL query functions, testable with in-memory SQLite.
- Implemented `commands/query.py` with Rich table output for both query modes.
- Wired up `--component` / `-c`, `--version`, `--license` / `-l` options in `main.py` (mutually exclusive).
- Component search uses exact name match; license search is case-insensitive and matches SPDX id or freeform name.
- Added 17 new tests (11 repository + 6 CLI integration) — all 38 tests passing, ruff clean.

Result: Helpful — query command works end-to-end with clean layering (repository → command → CLI).
