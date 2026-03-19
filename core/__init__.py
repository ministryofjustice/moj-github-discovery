"""Core library modules for the moj-github-discovery audit toolkit.

Sub-modules
-----------
models       — Pydantic data models (RepoData, FieldsConfig, …)
http_client  — HTTP session, retry, and rate-limit handling
github_api   — GitHub REST API endpoint classes
storage      — SQLite persistence (BaseStorage, SqliteStorage)
transforms   — Pure data enrichment and flag generation
collector    — Orchestrates API collection and incremental persistence
compiler     — Reads the database and writes Excel/CSV output
"""
