# IOC CI/CD Pipeline - TODO List

## Current Status: Refactoring to Hunting Publishers Complete

Last Updated: 2026-02-18

---

## ✅ Completed Phases

### Phase 1: Core Infrastructure ✅
- [x] `src/__init__.py`
- [x] `src/models.py` - Data classes (IOC, SourceScore, EnrichmentResult, ValidationReport, HuntResult)
- [x] `src/parser.py` - Auto-detection of IOC types using validators library
- [x] `src/config.py` - Configuration loader from environment variables
- [x] `src/logging_setup.py` - GitHub Actions-aware structured logging
- [x] `src/rate_limiter.py` - Token bucket rate limiter with daily budgets

### Phase 2: Enrichment ✅
- [x] `src/enrichment/__init__.py`
- [x] `src/enrichment/base.py` - Abstract TIEnrichmentClient
- [x] `src/enrichment/virustotal.py` - VirusTotal API v3 client (vt-py)
- [x] `src/enrichment/abuseipdb.py` - AbuseIPDB API v2 client (aiohttp)
- [x] `src/enrichment/otx.py` - OTX AlienVault client (OTXv2 SDK)
- [x] `src/enrichment/aggregator.py` - Weighted confidence scoring with ENRICHMENT_REGISTRY

### Phase 3: Hunting Publishers ✅
- [x] `src/publishers/__init__.py`
- [x] `src/publishers/base.py` - HuntPublisher ABC (`hunt()`, `name()`)
- [x] `src/publishers/splunk.py` - Splunk REST API hunter (SPL queries, no SDK)
- [x] `src/publishers/elastic.py` - Elasticsearch REST API hunter (ECS queries, no SDK)

### Phase 4: Reporting ✅
- [x] `src/reporting/__init__.py`
- [x] `src/reporting/pr_comment.py` - Markdown PR comment formatter

### Phase 5: CLI & Action ✅
- [x] `src/cli.py` - CLI entrypoint: validate/inventory/publish commands; PUBLISHER_REGISTRY
- [x] `Dockerfile` - Docker-based action (Python 3.12)
- [x] `action.yml` - GitHub Action metadata (enrichment_sources, publishers, max_ioc_age_days inputs)

### Phase 6: Workflows ✅
- [x] `.github/workflows/validate.yml` - PR validation workflow (enrichment + PR comment)
- [x] `.github/workflows/deploy.yml` - Post-merge hunt workflow (inventory + hunt phases)

### Phase 7: Testing ✅
- [x] `tests/conftest.py` - Shared fixtures
- [x] `tests/test_parser.py` - 18 tests (auto-detection, validation, dedup)
- [x] `tests/test_models.py` - 11 tests (dataclass equality, hashing, HuntResult)
- [x] `tests/test_rate_limiter.py` - 10 tests (token bucket, daily budget)
- [x] `tests/test_enrichment/test_virustotal.py` - 13 tests
- [x] `tests/test_enrichment/test_abuseipdb.py` - 11 tests
- [x] `tests/test_enrichment/test_otx.py` - 12 tests
- [x] `tests/test_enrichment/test_aggregator.py` - 10 tests (incl. enabled_sources)
- [x] `tests/test_enrichment/test_enrich_all.py` - 6 tests
- [x] `tests/test_publishers/test_splunk.py` - 17 tests (SPL generation, REST mocking)
- [x] `tests/test_publishers/test_elastic.py` - 20 tests (ECS queries, REST mocking)
- [x] `tests/test_reporting/test_pr_comment.py` - 13 tests
- [x] `tests/test_cli.py` - 35 tests (validate/inventory/publish commands, age-based CSV)
- [x] `tests/fixtures/` - Sample IOC files and mock responses
- [x] **189 tests total, 95% coverage** (target was 85%)

### Phase 8: Documentation ✅
- [x] `README.md` - Complete user guide (updated for hunting architecture)
- [x] `CLAUDE.md` - Development instructions (updated)
- [x] `PROJECT_SPEC.md` - Product specification (updated)
- [x] `WORKFLOW.md` - Detailed workflow documentation (updated)
- [x] `TODO.md` - This file
- [x] `iocs/indicators.txt` - Sample IOC file
- [x] `.gitignore`
- [x] `pyproject.toml` (removed pymisp, pycti, stix2; kept aiohttp)

---

## Refactoring Changes (2026-02-18)

### Architecture Shift: TI Platform Publishers → Security Hunting Publishers
- **Removed**: MISP publisher (`src/publishers/misp.py`), OpenCTI publisher (`src/publishers/opencti.py`)
- **Added**: Splunk hunter (`src/publishers/splunk.py`), Elastic hunter (`src/publishers/elastic.py`)
- **Changed**: Deploy Phase 2 now _hunts_ for IOCs in SIEM/EDR instead of _pushing_ to TI platforms
- **Hunt results**: Logged in workflow run only (not PR comments)

### CSV Schema Change
- **Removed columns**: `status`, `deployed_to`
- **Added column**: `last_hunted_date` (updated after each successful hunt)
- **Selection logic**: Age-based (`added_date >= now - MAX_IOC_AGE_DAYS`) instead of status-based

### Modular Architecture
- **`ENRICHMENT_REGISTRY`** in `aggregator.py`: selectable sources via `ENRICHMENT_SOURCES` env var
- **`PUBLISHER_REGISTRY`** in `cli.py`: selectable publishers via `PUBLISHERS` env var

---

## Future Enhancements (v0.2.0+)

- [ ] IPv6 support
- [ ] Additional TI enrichment sources (Shodan, GreyNoise)
- [ ] Additional hunting publishers (CrowdStrike Falcon, Microsoft Sentinel, Velociraptor)
- [ ] Scheduled re-validation of existing IOCs (cron workflow querying master CSV)
- [ ] STIX 2.1 input format support
- [ ] Batch size limits for large IOC lists
- [ ] Incremental enrichment caching (avoid re-enriching same IOC across PR pushes)
- [ ] Slack/email notifications on hunt results
- [ ] Master CSV export/analysis tools
