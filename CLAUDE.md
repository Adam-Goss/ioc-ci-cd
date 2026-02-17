# IOC CI/CD Pipeline - Claude Code Instructions

## Project Overview

This is a GitHub Action CI/CD pipeline that automates the ingestion, validation, enrichment, and deployment of Indicators of Compromise (IOCs). Security analysts commit a plain-text IOC list to the repo, a PR triggers automated enrichment against three threat intelligence sources (VirusTotal, AbuseIPDB, OTX AlienVault), and merging the PR pushes validated IOCs to MISP and OpenCTI.

**Tech Stack**: Python 3.12, Docker-based GitHub Action, async I/O

## Repository Structure

```
ioc-ci-cd/
├── .github/workflows/      # GitHub Actions workflows
│   ├── validate.yml        # PR validation (enrichment + comment)
│   └── deploy.yml          # Post-merge deployment to MISP/OpenCTI
├── iocs/
│   ├── indicators.txt      # Plain text IOC input (no prefixes) - auto-cleared after deploy
│   └── master-indicators.csv  # Master inventory (permanent audit trail)
├── src/
│   ├── models.py           # Data classes
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
│   │   └── aggregator.py   # Weighted confidence scoring
│   ├── publishers/
│   │   ├── misp.py         # MISP publisher (pymisp)
│   │   └── opencti.py      # OpenCTI publisher (pycti)
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
- **Fail conditions**: Malformed IOCs, or below threshold without override
- **Permissions**: `contents: read`, `pull-requests: write`

### 2. `deploy.yml` (Post-merge deployment)
- **Trigger**: Push to `main` when `iocs/indicators.txt` changes
- **Actions**:
  1. Diffs new IOCs
  2. Re-enriches (fresh scores)
  3. Pushes to MISP + OpenCTI
  4. Appends ALL IOCs to `master-indicators.csv` with metadata
  5. Clears `indicators.txt` for next batch
  6. Commits changes with `[skip ci]`
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

## Secrets & Configuration

### Required Secrets
- Both workflows: `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`
- Deploy only: `MISP_URL`, `MISP_API_KEY`, `OPENCTI_URL`, `OPENCTI_TOKEN`

### Optional Variables
- `CONFIDENCE_THRESHOLD` (default: 70)
- `MISP_VERIFY_SSL`, `MISP_DISTRIBUTION`, `MISP_AUTO_PUBLISH`
- `WEIGHT_VT`, `WEIGHT_ABUSEIPDB`, `WEIGHT_OTX`

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
```

## Code Conventions

- **Async-first**: All TI enrichment is async (concurrent lookups per IOC)
- **Error handling**: TI source failures are non-fatal; source marked unavailable, continue with others
- **Logging**: GitHub Actions `::error::`/`::warning::` prefixes for inline annotations
- **Type hints**: All functions fully typed (mypy strict mode)
- **Imports**: Sorted with `ruff` (I rule)

## Implementation Status

### ✅ All Phases Complete
- [x] Data models (`models.py`)
- [x] IOC parser with auto-detection (`parser.py`)
- [x] Configuration loader (`config.py`)
- [x] GitHub Actions logging (`logging_setup.py`)
- [x] Token bucket rate limiter (`rate_limiter.py`)
- [x] Enrichment clients (VT, AbuseIPDB, OTX)
- [x] Confidence aggregator
- [x] Publishers (MISP, OpenCTI)
- [x] PR comment formatter
- [x] CLI entrypoint with master inventory support
- [x] GitHub Action metadata (`action.yml`, `Dockerfile`)
- [x] Workflows (`validate.yml`, `deploy.yml`)
- [x] README.md, PROJECT_SPEC.md, WORKFLOW.md
- [x] Master inventory system (`master-indicators.csv`)
- [x] Automatic cleanup of `indicators.txt` after deployment
- [x] Test suite: **160 tests, 96% coverage**

## Testing

### Test Suite (160 tests, 96% coverage)
- **Parser**: 18 tests (auto-detection, validation, dedup, edge cases)
- **Models**: 8 tests (dataclass equality, hashing, set dedup)
- **Rate limiter**: 10 tests (token bucket, daily budget, concurrency)
- **Enrichment**: 41 tests (VT, AbuseIPDB, OTX clients + aggregator)
- **Publishers**: 30 tests (MISP event creation, OpenCTI observables, retry logic)
- **Reporting**: 13 tests (PR comment formatting, GitHub outputs)
- **CLI**: 21 tests (validate/publish commands, master CSV inventory)
- **Fixtures**: Sample IOC files and mock API responses in `tests/fixtures/`

## Common Tasks

### Adding a New TI Source
1. Create `src/enrichment/newsource.py` extending `TIEnrichmentClient`
2. Implement `enrich()` and `supports()` methods
3. Add to `RATE_LIMITS` in `rate_limiter.py`
4. Update `aggregator.py` to include the new client
5. Add weight to `PipelineConfig` in `config.py`
6. Update tests

### Adding a New IOC Type
1. Add to `IOCType` enum in `models.py`
2. Update `detect_ioc_type()` in `parser.py` with validation logic
3. Update each TI client's `supports()` method
4. Add MISP/OpenCTI type mappings in publishers
5. Update tests

### Debugging GitHub Actions
- Check workflow run logs for `::error::`/`::warning::` annotations
- PR comments show enrichment results and source availability
- Set `ACTIONS_STEP_DEBUG=true` secret for verbose logging

## Performance Notes

- **Concurrency**: Each IOC is enriched concurrently across all 3 sources using `asyncio.gather()`
- **Rate limiting**: Per-source token bucket with configurable rates
- **Docker startup**: ~30-60s overhead for action (pip install cached in image)
- **Re-enrichment**: Deploy workflow re-runs enrichment to avoid stale data from PR

## Security Considerations

- **API keys**: Stored as GitHub secrets, never logged
- **TLS verification**: MISP SSL verification configurable via `MISP_VERIFY_SSL`
- **Input validation**: All IOCs validated with `validators` library before enrichment
- **Malformed input**: Rejected at parser stage, reported in PR comment

## Master IOC Inventory

The pipeline maintains a **permanent audit trail** at `iocs/master-indicators.csv`:

**Features**:
- Appends ALL processed IOCs (passed and failed)
- Deduplication across batches (checks before appending)
- Tracks deployment status (MISP,OpenCTI or N/A)
- Includes timestamp and commit SHA for traceability

**CSV Format**:
```csv
ioc_type,ioc_value,confidence_score,deployed_to,added_date,commit_sha
domain,evil.com,85.23,MISP,OpenCTI,2026-02-17 14:30:00,abc12345
ip,192.0.2.1,45.67,N/A,2026-02-17 14:30:00,abc12345
```

**Workflow**:
1. IOCs added to `indicators.txt`
2. PR validation enriches and reports
3. Merge deploys to MISP/OpenCTI
4. All IOCs appended to `master-indicators.csv`
5. `indicators.txt` automatically cleared (ready for next batch)

See [WORKFLOW.md](WORKFLOW.md) for complete flow diagram.

## Future Enhancements

- IPv6 support
- Additional TI sources (Shodan, GreyNoise, etc.)
- Scheduled re-validation of existing IOCs (check master CSV periodically)
- Slack/email notifications on deployment
- Support for STIX 2.1 input format
- Batch size limits for large IOC lists
- Incremental enrichment (cache results between PR updates)
- Master CSV export/analysis tools
