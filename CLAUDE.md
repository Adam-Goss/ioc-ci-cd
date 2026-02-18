# IOC CI/CD Pipeline - Claude Code Instructions

## Project Overview

This is a GitHub Action CI/CD pipeline that automates the ingestion, validation, enrichment, and hunting of Indicators of Compromise (IOCs). Security analysts commit a plain-text IOC list to the repo, a PR triggers automated enrichment against three threat intelligence sources (VirusTotal, AbuseIPDB, OTX AlienVault), and merging the PR hunts for those IOCs in Splunk and Elasticsearch.

**Tech Stack**: Python 3.12, Docker-based GitHub Action, async I/O

## Repository Structure

```
ioc-ci-cd/
├── .github/workflows/      # GitHub Actions workflows
│   ├── validate.yml        # PR validation (enrichment + comment)
│   └── deploy.yml          # Post-merge inventory + hunting
├── iocs/
│   ├── indicators.txt      # Plain text IOC input (no prefixes) - auto-cleared after deploy
│   └── master-indicators.csv  # Master inventory (permanent audit trail)
├── src/
│   ├── models.py           # Data classes (IOC, EnrichmentResult, HuntResult, etc.)
│   ├── parser.py           # Auto-detect IOC types from raw values
│   ├── config.py           # Load env vars
│   ├── logging_setup.py    # GitHub Actions logging
│   ├── rate_limiter.py     # Token bucket rate limiter
│   ├── cli.py              # CLI entrypoint
│   ├── enrichment/
│   │   ├── base.py         # Abstract TI client
│   │   ├── virustotal.py   # VT API v3 client
│   │   ├── abuseipdb.py    # AbuseIPDB client
│   │   ├── otx.py          # OTX AlienVault client
│   │   └── aggregator.py   # Weighted confidence scoring + ENRICHMENT_REGISTRY
│   ├── publishers/
│   │   ├── base.py         # HuntPublisher abstract base class
│   │   ├── splunk.py       # Splunk REST API hunter
│   │   └── elastic.py      # Elasticsearch REST API hunter
│   └── reporting/
│       └── pr_comment.py   # Markdown PR comment formatter
├── tests/                  # Pytest suite with fixtures
├── pyproject.toml
├── Dockerfile
├── action.yml              # GitHub Action metadata
└── README.md
```

## IOC Input Format

**File**: `iocs/indicators.txt`

**Format**: One raw value per line, **no type prefixes**. The parser auto-detects the type.

```
# Incident 2024-IR-0042 - Phishing campaign
185.220.101.34
login-secure-update.com
http://login-secure-update.com/office365/signin.php
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
d41d8cd98f00b204e9800998ecf8427e
```

- Lines starting with `#` are comments
- Empty lines are ignored
- Case-insensitive deduplication

### Auto-Detection Order
1. `validators.url()` → URL
2. `validators.ipv4()` → IPv4
3. Hex length 64 + `validators.sha256()` → SHA256
4. Hex length 40 + `validators.sha1()` → SHA1
5. Hex length 32 + `validators.md5()` → MD5
6. `validators.domain()` → Domain
7. None matched → Malformed

## Workflows

### 1. `validate.yml` (PR validation)
- **Trigger**: PR opened/updated when `iocs/indicators.txt` changes
- **Actions**: Diffs new IOCs, parses, enriches against VT/AbuseIPDB/OTX, posts PR comment
- **Fail conditions**: None (malformed/below-threshold IOCs logged as warnings, reported in comment)
- **Permissions**: `contents: read`, `pull-requests: write`
- **Note**: Does NOT modify master inventory; that happens on merge

### 2. `deploy.yml` (Post-merge hunt)
- **Trigger**: Push to `main` when `iocs/indicators.txt` changes
- **Actions** (two-phase):
  1. **Phase 1 — Inventory**: Diffs new IOCs, enriches (fresh scores), appends ALL valid IOCs to `master-indicators.csv` with confidence level and `last_hunted_date` empty
  2. **Phase 2 — Hunt**: Reads IOCs within `MAX_IOC_AGE_DAYS` window from CSV, hunts across Splunk and Elastic, updates `last_hunted_date`
  3. **Cleanup**: Clears `indicators.txt`, commits changes with `[skip ci]`
- **Environment**: `production` (can add required reviewers)

## Enrichment Sources

### VirusTotal (weight: 0.45)
- **Library**: `vt-py` (async)
- **Score**: `(malicious + 0.5 * suspicious) / total_engines * 100`
- **Rate**: 4 req/min, 500/day (free tier)

### AbuseIPDB (weight: 0.25)
- **Library**: `aiohttp`
- **Score**: `abuseConfidenceScore` (0-100, direct)
- **Rate**: 60 req/min, 1000/day
- **Supports**: IP addresses only

### OTX AlienVault (weight: 0.30)
- **Library**: `OTXv2`
- **Score**: `min(100, log2(pulse_count + 1) * 15 + 20 if has_malware else 0)`
- **Rate**: 150 req/min

### Confidence Aggregation
Weighted average across **available** sources (weights renormalized when a source doesn't support the IOC type or errors out).

### Confidence Levels

IOCs are classified into three confidence levels based on their aggregated score:

- **Low**: 0–29 (likely benign or insufficient data)
- **Medium**: 30–69 (moderate confidence, may be malicious)
- **High**: 70–100 (high confidence malicious)

Each publisher independently filters IOCs by a configurable minimum confidence level via `{PUBLISHER}_MIN_CONFIDENCE_LEVEL` env var (default: `low` for both Splunk and Elastic).

## Hunting Publishers

### Splunk (`src/publishers/splunk.py`)
- **API**: Splunk REST API (no SDK dependency)
- **Flow**: POST search job → poll status → GET results
- **SPL**: Per-IOC-type templates with `stats count earliest latest`
- **Config**: `SPLUNK_URL`, `SPLUNK_TOKEN`, `SPLUNK_INDEX` (default: `main`)

### Elasticsearch (`src/publishers/elastic.py`)
- **API**: Elasticsearch REST `_search` (no SDK dependency)
- **Query**: Bool query with ECS field `should` clauses + `@timestamp` range filter
- **Config**: `ELASTIC_URL`, `ELASTIC_API_KEY`, `ELASTIC_INDEX` (default: `*`), `ELASTIC_VERIFY_SSL`

### HuntPublisher Interface (`src/publishers/base.py`)
```python
class HuntPublisher(ABC):
    @abstractmethod
    async def hunt(self, results: list[EnrichmentResult]) -> list[HuntResult]: ...
    @abstractmethod
    def name(self) -> str: ...
```

### Hunt Results
Hunt results appear in **deploy workflow logs only** (not PR comments).

## Secrets & Configuration

### Required Secrets
- Both workflows: `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`
- Deploy only: `SPLUNK_URL`, `SPLUNK_TOKEN` (if using Splunk)
- Deploy only: `ELASTIC_URL`, `ELASTIC_API_KEY` (if using Elastic)

### Optional Variables / Configuration
- `ENRICHMENT_SOURCES` (default: `virustotal,abuseipdb,otx`) — comma-separated sources
- `PUBLISHERS` (default: `splunk,elastic`) — comma-separated publishers
- `MAX_IOC_AGE_DAYS` (default: `30`) — age window for hunting
- `SPLUNK_INDEX` (default: `main`) — Splunk index to search
- `ELASTIC_INDEX` (default: `*`) — Elastic index pattern
- `ELASTIC_VERIFY_SSL` (default: `true`) — Verify Elastic TLS cert
- `SPLUNK_MIN_CONFIDENCE_LEVEL` (default: `low`) — min confidence for Splunk hunting
- `ELASTIC_MIN_CONFIDENCE_LEVEL` (default: `low`) — min confidence for Elastic hunting
- `WEIGHT_VT`, `WEIGHT_ABUSEIPDB`, `WEIGHT_OTX` — scoring weights

## Development

### Setup
```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Run Tests
```bash
pytest tests/ -v --cov=src --cov-fail-under=85
```

### Linting
```bash
ruff check src/ tests/
mypy src/
```

### Local Testing
```bash
# Validate IOCs locally
export VT_API_KEY="..."
export ABUSEIPDB_API_KEY="..."
export OTX_API_KEY="..."

python -m src.cli validate iocs/indicators.txt --threshold=70

# Inventory IOCs (Phase 1 of deploy)
python -m src.cli inventory iocs/indicators.txt

# Hunt from master CSV (Phase 2 of deploy)
export SPLUNK_URL="https://splunk.example.com:8089"
export SPLUNK_TOKEN="..."
export ELASTIC_URL="https://elastic.example.com:9200"
export ELASTIC_API_KEY="..."
export MAX_IOC_AGE_DAYS="30"

python -m src.cli publish
```

## Code Conventions

- **Async-first**: All TI enrichment and hunting is async (concurrent per IOC)
- **Registry pattern**: `ENRICHMENT_REGISTRY` and `PUBLISHER_REGISTRY` dicts enable modular source/publisher selection
- **Error handling**: TI source failures are non-fatal; source marked unavailable, continue with others. Hunt failures are non-fatal; logged as warnings
- **Logging**: GitHub Actions `::error::`/`::warning::` prefixes for inline annotations
- **Type hints**: All functions fully typed (mypy strict mode)
- **Imports**: Sorted with `ruff` (I rule)

## Implementation Status

### ✅ All Phases Complete
- [x] Data models (`models.py`) — includes `HuntResult`
- [x] IOC parser with auto-detection (`parser.py`)
- [x] Configuration loader (`config.py`) — modular enrichment/publisher selection
- [x] GitHub Actions logging (`logging_setup.py`)
- [x] Token bucket rate limiter (`rate_limiter.py`)
- [x] Enrichment clients (VT, AbuseIPDB, OTX) + `ENRICHMENT_REGISTRY`
- [x] Confidence aggregator with `enabled_sources` support
- [x] Hunting publishers (Splunk, Elastic) via `HuntPublisher` interface
- [x] PR comment formatter
- [x] CLI entrypoint with validate/inventory/publish commands
- [x] GitHub Action metadata (`action.yml`, `Dockerfile`)
- [x] Workflows (`validate.yml`, `deploy.yml`)
- [x] README.md, PROJECT_SPEC.md, WORKFLOW.md
- [x] Master inventory system (`master-indicators.csv`) — age-based selection
- [x] Automatic cleanup of `indicators.txt` after deployment
- [x] Test suite: **189 tests, 95% coverage**

## Testing

### Test Suite (189 tests, 95% coverage)
- **Parser**: 18 tests (auto-detection, validation, dedup, edge cases)
- **Models**: 11 tests (dataclass equality, hashing, set dedup, HuntResult)
- **Rate limiter**: 10 tests (token bucket, daily budget, concurrency)
- **Enrichment**: 44 tests (VT, AbuseIPDB, OTX clients + aggregator + enabled_sources)
- **Publishers**: 37 tests (Splunk SPL generation, REST mocking, Elastic query gen, REST mocking)
- **Reporting**: 13 tests (PR comment formatting, GitHub outputs)
- **CLI**: 38 tests (validate/inventory/publish commands, master CSV helpers)
- **Config**: 6 tests (confidence level validation, load_config)
- **Fixtures**: Sample IOC files and mock API responses in `tests/fixtures/`

## Common Tasks

### Adding a New TI Source
1. Create `src/enrichment/newsource.py` extending `TIEnrichmentClient`
2. Implement `enrich()` and `supports()` methods
3. Add to `RATE_LIMITS` in `rate_limiter.py`
4. Add to `ENRICHMENT_REGISTRY` in `aggregator.py`
5. Add API key field to `PipelineConfig` in `config.py`
6. Add to `_ENRICHMENT_SOURCE_KEY_MAP` in `config.py`
7. Update tests

### Adding a New Hunting Publisher
1. Create `src/publishers/newpublisher.py` extending `HuntPublisher`
2. Implement `hunt()` and `name()` methods
3. Add to `PUBLISHER_REGISTRY` in `cli.py`
4. Add required env vars to `_PUBLISHER_REQUIRED_VARS` in `config.py`
5. Add credentials to `PipelineConfig` dataclass
6. Add to `deploy.yml` env vars
7. Update tests

### Adding a New IOC Type
1. Add to `IOCType` enum in `models.py`
2. Update `detect_ioc_type()` in `parser.py` with validation logic
3. Update each TI client's `supports()` method
4. Add SPL templates and ECS field mappings in publishers
5. Update tests

### Debugging GitHub Actions
- Check workflow run logs for `::error::`/`::warning::` annotations
- PR comments show enrichment results and source availability
- Hunt results appear only in deploy workflow logs
- Set `ACTIONS_STEP_DEBUG=true` secret for verbose logging

## Performance Notes

- **Concurrency**: Each IOC is enriched concurrently across all enabled sources using `asyncio.gather()`
- **Rate limiting**: Per-source token bucket with configurable rates
- **Docker startup**: ~30-60s overhead for action (pip install cached in image)
- **Re-enrichment**: Deploy workflow re-runs enrichment to avoid stale data from PR

## Security Considerations

- **API keys**: Stored as GitHub secrets, never logged
- **TLS verification**: Elastic SSL verification configurable via `ELASTIC_VERIFY_SSL`
- **Input validation**: All IOCs validated with `validators` library before enrichment
- **Malformed input**: Rejected at parser stage, reported in PR comment

## Master IOC Inventory

The pipeline maintains a **permanent audit trail** at `iocs/master-indicators.csv`:

**Features**:
- Appends ALL valid IOCs with confidence scores and levels
- Deduplication across batches (checks before appending)
- Age-based selection for hunting (`added_date` within `MAX_IOC_AGE_DAYS`)
- Tracks when each IOC was last hunted (`last_hunted_date`)
- Includes timestamp and commit SHA for traceability

**CSV Format**:
```csv
ioc_type,ioc_value,confidence_score,confidence_level,added_date,last_hunted_date,commit_sha
domain,evil.com,85.23,high,2026-02-17 14:30:00,2026-02-18 08:00:00,abc12345
ip,192.0.2.1,45.67,medium,2026-02-17 14:30:00,,abc12345
ip,10.0.0.1,15.00,low,2026-02-17 14:30:00,,abc12345
```

**Columns**:
- `confidence_level`: low (<30), medium (30-69), high (70+)
- `last_hunted_date`: Empty until first hunt; updated on each successful hunt
- `commit_sha`: Short SHA of the commit that added this IOC

**Workflow**:
1. IOCs added to `indicators.txt`
2. PR validation enriches and reports (master CSV not touched)
3. Merge triggers two-phase deploy:
   - **Inventory**: Enrich IOCs, append to `master-indicators.csv`
   - **Hunt**: Read IOCs within age window, hunt in Splunk/Elastic, update `last_hunted_date`
4. `indicators.txt` automatically cleared (ready for next batch)

See [WORKFLOW.md](WORKFLOW.md) for complete flow diagram.

## Future Enhancements

- IPv6 support
- Additional TI sources (Shodan, GreyNoise, etc.)
- Additional hunting publishers (CrowdStrike, Microsoft Sentinel, Velociraptor)
- Scheduled re-hunting of existing IOCs (check master CSV periodically)
- Slack/email notifications on hunt hits
- Support for STIX 2.1 input format
- Batch size limits for large IOC lists
- Hunt result summary report in PR comment
- Incremental enrichment (cache results between PR updates)
- Master CSV export/analysis tools
