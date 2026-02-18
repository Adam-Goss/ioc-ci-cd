# Changelog

All notable changes to the IOC CI/CD Pipeline project will be documented in this file.

## [0.3.0] - 2026-02-18

### Changed (Breaking)
- **Publisher architecture**: Replaced TI platform publishers (MISP, OpenCTI) with security hunting publishers (Splunk, Elasticsearch)
  - Deploy Phase 2 now _hunts_ for IOCs in configured SIEMs instead of pushing to TI platforms
  - Hunt results are logged to workflow run only (not PR comments)
- **CSV schema**: Removed `status` and `deployed_to` columns; added `last_hunted_date`
  - New format: `ioc_type,ioc_value,confidence_score,confidence_level,added_date,last_hunted_date,commit_sha`
- **IOC selection**: Age-based selection replaces status-based — Phase 2 hunts IOCs within `MAX_IOC_AGE_DAYS` window (default: 30)
- **Modular architecture**: Enrichment sources and hunting publishers now selectable via `ENRICHMENT_SOURCES` and `PUBLISHERS` env vars
- `pyproject.toml`: Removed `pymisp`, `pycti`, `stix2` dependencies

### Added
- `HuntResult` dataclass in `models.py` (platform, hits_found, earliest_hit, latest_hit, sample_events, query_used)
- `HuntPublisher` ABC in `publishers/base.py` (replaces `Publisher`)
- Splunk hunter (`publishers/splunk.py`) — SPL queries via REST API, per-IOC-type templates
- Elasticsearch hunter (`publishers/elastic.py`) — ECS-mapped queries via REST API
- `ENRICHMENT_REGISTRY` in `aggregator.py` — enables modular source selection
- `PUBLISHER_REGISTRY` in `cli.py` — enables modular publisher selection
- `read_iocs_by_age()` and `update_csv_last_hunted()` CSV helpers (replace `read_pending_iocs_from_csv` / `update_csv_deployment_status`)
- New config fields: `enrichment_sources`, `publishers`, `max_ioc_age_days`, `splunk_url`, `splunk_token`, `splunk_index`, `elastic_url`, `elastic_api_key`, `elastic_index`, `elastic_verify_ssl`, `publisher_min_confidence`
- New `action.yml` inputs: `enrichment_sources`, `publishers`, `max_ioc_age_days`

### Removed
- `src/publishers/misp.py` — MISP publisher
- `src/publishers/opencti.py` — OpenCTI publisher
- `tests/test_publishers/test_misp.py`
- `tests/test_publishers/test_opencti.py`
- Config fields: `misp_url`, `misp_api_key`, `misp_verify_ssl`, `misp_distribution`, `misp_auto_publish`, `opencti_url`, `opencti_token`

### Testing
- 189 tests total, 95% coverage (was 160 tests, 96%)
- New: `tests/test_publishers/test_splunk.py` (17 tests) — SPL generation, aioresponses HTTP mocking
- New: `tests/test_publishers/test_elastic.py` (20 tests) — ECS query generation, aioresponses HTTP mocking
- Updated: `tests/test_cli.py` — age-based CSV helpers, `patch.dict(PUBLISHER_REGISTRY)` pattern

---

## [0.2.0] - 2026-02-17

### Changed
- **Two-phase deployment**: Deploy workflow split into Inventory (enrich + write to CSV) and Deploy (publish from CSV)
- **Per-publisher confidence filtering**: Each publisher independently filters by configurable confidence level
  - MISP: defaults to `medium` (deploys medium + high IOCs)
  - OpenCTI: defaults to `high` (deploys only high confidence IOCs)
  - Configurable via `MISP_MIN_CONFIDENCE_LEVEL` and `OPENCTI_MIN_CONFIDENCE_LEVEL` env vars
- **Non-fatal validation**: PR validation no longer fails on malformed or below-threshold IOCs (warnings instead)
- **Non-fatal deployment**: Publisher failures no longer stop the pipeline; warnings embedded in commit message
- **Master CSV format**: Added `confidence_level` and `status` columns
  - `confidence_level`: low (<30), medium (30-69), high (70+)
  - `status`: pending (after inventory) → deployed (after publish)
- CLI now supports three commands: `validate`, `inventory`, `publish`

### Added
- `ConfidenceLevel` enum in `models.py` with `get_confidence_level()` helper
- Per-publisher confidence level configuration in `config.py`
- `inventory` CLI command (Phase 1 of deploy)
- `publish` CLI command reads pending IOCs from master CSV (Phase 2 of deploy)
- `deploy_warnings.txt` mechanism for communicating publisher failures to git commit step
- New helper functions: `read_pending_iocs_from_csv()`, `update_csv_deployment_status()`, `filter_by_publisher_confidence()`
- Tests for confidence levels, config validation, inventory/publish commands, and partial failure scenarios

---

## [0.1.0] - 2026-02-17

### Added
- Initial release of IOC CI/CD Pipeline
- Auto-detection of 6 IOC types (IPv4, Domain, URL, MD5, SHA1, SHA256)
- Multi-source enrichment (VirusTotal, AbuseIPDB, OTX AlienVault)
- Weighted confidence scoring with configurable thresholds
- MISP publisher integration
- OpenCTI publisher integration
- PR-based validation workflow with enrichment report comments
- Automated deployment workflow on merge to main
- **Master IOC inventory** (`iocs/master-indicators.csv`)
  - Tracks all processed IOCs with metadata
  - Includes IOC type, value, confidence score, deployment status, timestamp, and commit SHA
  - Automatic deduplication across batches
- **Automatic cleanup** of `iocs/indicators.txt` after deployment
- Docker-based GitHub Action
- Comprehensive documentation (README, CLAUDE.md, PROJECT_SPEC.md)

### Features
- Async concurrent enrichment across all TI sources
- Token bucket rate limiting per source
- GitHub Actions-aware logging with annotations
- Configurable via environment variables
- Re-enrichment on deployment to avoid stale data
- Case-insensitive deduplication
- Retry logic for API calls and publisher connections

### Testing
- 160 unit and integration tests across all modules
- 96% code coverage (target was 85%)
- Test suite covers: parser, models, rate limiter, enrichment clients, aggregator, publishers, reporting, CLI
- Mock-based testing with pytest, pytest-asyncio, pytest-cov
- Test fixtures for sample IOC files and mock API responses

### Documentation
- Complete user guide (README.md)
- Developer instructions (CLAUDE.md)
- Product specification (PROJECT_SPEC.md)
- Detailed workflow documentation (WORKFLOW.md)
- Sample IOC file with examples

### Dependencies
- Python 3.12
- validators, vt-py, OTXv2, pymisp, pycti, stix2, aiohttp, requests
- pytest, pytest-asyncio, pytest-cov, aioresponses, responses, ruff, mypy (dev)

---

## Future Enhancements

Planned for future releases:

- [ ] IPv6 support
- [ ] Additional TI sources (Shodan, GreyNoise, URLhaus, PhishTank)
- [ ] STIX 2.1 input format support
- [ ] Defanged IOC support (auto-refang `hxxp://`, `[.]`, `[:]//`)
- [ ] CI/CD for the pipeline itself
- [ ] Scheduled re-validation of existing IOCs
- [ ] Slack/email notifications
- [ ] Metrics dashboard
- [ ] Custom IOC types (Bitcoin addresses, email addresses)
