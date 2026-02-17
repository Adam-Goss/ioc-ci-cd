# IOC CI/CD Pipeline - Product Requirements & Specification

## Executive Summary

**Project Name**: IOC CI/CD Pipeline
**Version**: 0.1.0
**Status**: Complete
**Target Deployment**: GitHub Actions (Docker-based action)

### Purpose
Automate the ingestion, validation, enrichment, and deployment of Indicators of Compromise (IOCs) from security analysts. Replace manual, error-prone IOC triage with a reviewable, auditable, Git-based pipeline.

### Key Features
- **Auto-detection** of IOC types (IP, domain, URL, hash)
- **Multi-source enrichment** via VirusTotal, AbuseIPDB, OTX AlienVault
- **PR-based review gate** with automated enrichment reports
- **Automated deployment** to MISP and OpenCTI on merge
- **Configurable confidence thresholds** with override capability

---

## Product Requirements

### Functional Requirements

#### FR-1: IOC Ingestion
- **FR-1.1**: Accept plain text file with one IOC per line
- **FR-1.2**: Auto-detect IOC type (IP, domain, URL, MD5, SHA1, SHA256)
- **FR-1.3**: Support comments (lines starting with `#`)
- **FR-1.4**: Case-insensitive deduplication
- **FR-1.5**: Validate IOC format using `validators` library

#### FR-2: Threat Intelligence Enrichment
- **FR-2.1**: Query VirusTotal API v3 for all IOC types
- **FR-2.2**: Query AbuseIPDB for IP addresses
- **FR-2.3**: Query OTX AlienVault for all IOC types
- **FR-2.4**: Enrich IOCs concurrently (async I/O)
- **FR-2.5**: Normalize scores from each source to 0-100 scale
- **FR-2.6**: Compute weighted confidence score across sources

#### FR-3: PR Validation Workflow
- **FR-3.1**: Trigger on PR when `iocs/indicators.txt` changes
- **FR-3.2**: Diff against main to find only new IOCs
- **FR-3.3**: Parse and validate IOC format
- **FR-3.4**: Enrich new IOCs against TI sources
- **FR-3.5**: Post enrichment report as PR comment (idempotent updates)
- **FR-3.6**: Warn (not fail) if IOCs are malformed — reported in PR comment
- **FR-3.7**: Warn (not fail) if IOCs below threshold — still recorded in master CSV

#### FR-4: Deployment Workflow (Two-Phase)
- **FR-4.1**: Trigger on push to main when `iocs/indicators.txt` changes
- **FR-4.2**: Diff against previous commit to find new IOCs
- **FR-4.3**: Phase 1 (Inventory): Enrich IOCs, append ALL valid IOCs to master CSV with `status=pending` and confidence level
- **FR-4.4**: Phase 2 (Deploy): Read pending IOCs from master CSV, filter independently per publisher by configurable confidence level
- **FR-4.5**: Create MISP event with IOCs meeting MISP confidence level (default: medium+)
- **FR-4.6**: Create OpenCTI observables for IOCs meeting OpenCTI confidence level (default: high only)
- **FR-4.7**: Use GitHub Environment for deployment gate
- **FR-4.8**: Publisher failures are non-fatal — pipeline continues, warnings embedded in commit message
- **FR-4.9**: Clear `indicators.txt` and commit updated master CSV after processing

#### FR-5: MISP Integration
- **FR-5.1**: Create one MISP event per pipeline run
- **FR-5.2**: Title event with commit SHA and timestamp
- **FR-5.3**: Add each IOC as an attribute with correct type
- **FR-5.4**: Tag attributes with confidence scores
- **FR-5.5**: Apply TLP tags to event
- **FR-5.6**: Optionally auto-publish event

#### FR-6: OpenCTI Integration
- **FR-6.1**: Create STIX Cyber Observable (SCO) per IOC
- **FR-6.2**: Promote observables to indicators
- **FR-6.3**: Set `x_opencti_score` to confidence value
- **FR-6.4**: Apply labels from enrichment tags
- **FR-6.5**: Handle per-IOC errors gracefully

### Non-Functional Requirements

#### NFR-1: Performance
- **NFR-1.1**: Enrich 100 IOCs in under 5 minutes
- **NFR-1.2**: Concurrent enrichment per IOC (3 sources in parallel)
- **NFR-1.3**: Respect TI source rate limits (token bucket)

#### NFR-2: Reliability
- **NFR-2.1**: TI source failures are non-fatal (mark unavailable, continue)
- **NFR-2.2**: Retry on transient errors (3 attempts, exponential backoff)
- **NFR-2.3**: Publisher failures are non-fatal (pipeline continues, warning in commit message)

#### NFR-3: Security
- **NFR-3.1**: API keys stored as GitHub secrets
- **NFR-3.2**: No secrets logged or exposed in outputs
- **NFR-3.3**: TLS verification configurable for MISP
- **NFR-3.4**: Input validation before any external API calls

#### NFR-4: Usability
- **NFR-4.1**: PR comments are human-readable Markdown
- **NFR-4.2**: Enrichment results show per-source scores
- **NFR-4.3**: Malformed IOCs reported with line numbers and errors
- **NFR-4.4**: GitHub Actions annotations for errors/warnings

#### NFR-5: Maintainability
- **NFR-5.1**: 85%+ test coverage
- **NFR-5.2**: Type hints on all functions (mypy strict)
- **NFR-5.3**: Modular architecture (easy to add new sources/publishers)
- **NFR-5.4**: Comprehensive logging

---

## Technical Specification

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     GitHub Actions Runner                    │
│                                                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              Docker Container (Python 3.12)            │  │
│  │                                                         │  │
│  │  ┌─────────────┐      ┌──────────────────────────┐    │  │
│  │  │   Parser    │──────▶  IOC Auto-Detection       │    │  │
│  │  └─────────────┘      └──────────────────────────┘    │  │
│  │         │                                               │  │
│  │         ▼                                               │  │
│  │  ┌─────────────┐                                       │  │
│  │  │ Enrichment  │                                       │  │
│  │  │  Orchestr.  │                                       │  │
│  │  └─────────────┘                                       │  │
│  │    ╱    │    ╲                                         │  │
│  │   ╱     │     ╲                                        │  │
│  │  ▼      ▼      ▼                                       │  │
│  │ ┌──┐  ┌───┐  ┌────┐    (Concurrent async queries)     │  │
│  │ │VT│  │AIB│  │OTX │                                    │  │
│  │ └──┘  └───┘  └────┘                                    │  │
│  │   ╲     │     ╱                                        │  │
│  │    ╲    │    ╱                                         │  │
│  │     ▼   ▼   ▼                                          │  │
│  │  ┌─────────────┐                                       │  │
│  │  │ Confidence  │                                       │  │
│  │  │ Aggregator  │                                       │  │
│  │  └─────────────┘                                       │  │
│  │         │                                               │  │
│  │    ┌────┴────┐                                         │  │
│  │    ▼         ▼                                         │  │
│  │ ┌──────┐  ┌────────┐                                  │  │
│  │ │ MISP │  │OpenCTI │  (Publishers - deploy only)      │  │
│  │ └──────┘  └────────┘                                  │  │
│  └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

#### Validation Workflow
1. PR opened/updated → `validate.yml` triggered
2. Git diff extracts new lines from `iocs/indicators.txt`
3. Parser auto-detects types, validates format
4. Enrichment orchestrator creates clients with rate limiters
5. Each IOC enriched concurrently across 3 sources (async)
6. Aggregator computes weighted confidence score
7. PR comment formatter generates Markdown report
8. GitHub Actions posts comment (idempotent update)
9. Warnings issued for malformed or below-threshold IOCs (pipeline does not fail)

#### Deployment Workflow (Two-Phase)
1. PR merged → `deploy.yml` triggered
2. Git diff extracts newly merged lines
3. **Phase 1 — Inventory**: Parse, enrich, append all valid IOCs to master CSV as `pending`
4. **Phase 2 — Deploy**: Read pending IOCs from CSV, filter per-publisher by confidence level
5. MISP publisher creates event for IOCs meeting minimum level (default: medium+)
6. OpenCTI publisher creates observables for IOCs meeting minimum level (default: high only)
7. Publisher failures are caught — pipeline continues with remaining publishers
8. Master CSV updated: `status=deployed`, `deployed_to` records which platforms succeeded
9. `indicators.txt` cleared, changes committed with `[skip ci]`
10. If any publisher failed, warning embedded in commit message

### Data Models

```python
IOCType = Enum("IP", "DOMAIN", "HASH_MD5", "HASH_SHA1", "HASH_SHA256", "URL")

ConfidenceLevel = Enum("LOW", "MEDIUM", "HIGH")
  - LOW: 0-29, MEDIUM: 30-69, HIGH: 70-100
  - get_confidence_level(score) -> ConfidenceLevel

IOC:
  - ioc_type: IOCType
  - value: str
  - raw_line: str
  - line_number: int
  - hash_algorithm: Optional[HashAlgorithm]

SourceScore:
  - source_name: str (virustotal, abuseipdb, otx)
  - raw_score: float (0-100)
  - details: dict (source-specific metadata)
  - available: bool
  - error: Optional[str]

EnrichmentResult:
  - ioc: IOC
  - scores: list[SourceScore]
  - confidence: float (weighted aggregate)
  - above_threshold: bool
  - tags: list[str]

ValidationReport:
  - valid_iocs: list[IOC]
  - malformed_lines: list[tuple[line_num, raw_line, error]]
  - duplicates_removed: int
  - enrichment_results: list[EnrichmentResult]
  - threshold: float
  - override: bool
```

### API Specifications

#### VirusTotal API v3
- **Endpoint**: `https://www.virustotal.com/api/v3/{ip_addresses|domains|files|urls}/{id}`
- **Auth**: Header `x-apikey: {VT_API_KEY}`
- **Rate**: 4 req/min (free), 500/day
- **Score**: `(malicious + 0.5 * suspicious) / total * 100`

#### AbuseIPDB API v2
- **Endpoint**: `https://api.abuseipdb.com/api/v2/check`
- **Auth**: Header `Key: {ABUSEIPDB_API_KEY}`
- **Rate**: 1 req/sec (free), 1000/day
- **Score**: `abuseConfidenceScore` (0-100, direct)

#### OTX AlienVault
- **Library**: `OTXv2` SDK
- **Auth**: API key in constructor
- **Rate**: 10,000 req/hour
- **Score**: `min(100, log2(pulse_count+1)*15 + (20 if malware else 0))`

### Configuration

All configuration via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VT_API_KEY` | Yes | - | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | Yes | - | AbuseIPDB API key |
| `OTX_API_KEY` | Yes | - | OTX API key |
| `MISP_URL` | Deploy only | - | MISP instance URL |
| `MISP_API_KEY` | Deploy only | - | MISP auth key |
| `OPENCTI_URL` | Deploy only | - | OpenCTI URL |
| `OPENCTI_TOKEN` | Deploy only | - | OpenCTI token |
| `CONFIDENCE_THRESHOLD` | No | 70 | Min confidence for PR validation (0-100) |
| `MISP_MIN_CONFIDENCE_LEVEL` | No | medium | Min confidence level for MISP deployment (low/medium/high) |
| `OPENCTI_MIN_CONFIDENCE_LEVEL` | No | high | Min confidence level for OpenCTI deployment (low/medium/high) |
| `MISP_VERIFY_SSL` | No | true | Verify MISP TLS cert |
| `WEIGHT_VT` | No | 0.45 | VirusTotal weight |
| `WEIGHT_ABUSEIPDB` | No | 0.25 | AbuseIPDB weight |
| `WEIGHT_OTX` | No | 0.30 | OTX weight |

---

## Implementation Plan

### Phase 1: Core Infrastructure ✅
- [x] Data models (`models.py`)
- [x] IOC parser with auto-detection (`parser.py`)
- [x] Configuration loader (`config.py`)
- [x] Logging setup (`logging_setup.py`)
- [x] Rate limiter (`rate_limiter.py`)

### Phase 2: Enrichment ✅
- [x] Base enrichment client (`enrichment/base.py`)
- [x] VirusTotal client (`enrichment/virustotal.py`)
- [x] AbuseIPDB client (`enrichment/abuseipdb.py`)
- [x] OTX client (`enrichment/otx.py`)
- [x] Confidence aggregator (`enrichment/aggregator.py`)

### Phase 3: Publishers ✅
- [x] Base publisher (`publishers/base.py`)
- [x] MISP publisher (`publishers/misp.py`)
- [x] OpenCTI publisher (`publishers/opencti.py`)

### Phase 4: Reporting ✅
- [x] PR comment formatter (`reporting/pr_comment.py`)

### Phase 5: CLI & Action ✅
- [x] CLI entrypoint (`cli.py`)
- [x] Dockerfile
- [x] GitHub Action metadata (`action.yml`)

### Phase 6: Workflows ✅
- [x] Validation workflow (`.github/workflows/validate.yml`)
- [x] Deployment workflow (`.github/workflows/deploy.yml`)

### Phase 7: Testing ✅
- [x] Parser tests (`tests/test_parser.py`) - 18 tests
- [x] Enrichment tests (VT, AIB, OTX, aggregator) - 52 tests
- [x] Publisher tests (MISP, OpenCTI) - 30 tests
- [x] CLI tests - 21 tests
- [x] Reporting tests - 13 tests
- [x] Rate limiter tests - 10 tests
- [x] Model tests - 8 tests
- [x] Test fixtures (sample IOCs, mock responses)
- [x] **160 tests total, 96% coverage**

### Phase 8: Documentation ✅
- [x] README.md (user guide)
- [x] CLAUDE.md (developer instructions)
- [x] PROJECT_SPEC.md (this file)
- [x] WORKFLOW.md (detailed workflow documentation)
- [x] CHANGELOG.md (version history)
- [x] Example IOC file (`iocs/indicators.txt`)
- [x] GitHub repo setup instructions

---

## Testing Strategy

### Test Pyramid

```
                    ┌─────────────┐
                    │     E2E     │  (1-2 tests, real APIs optional)
                    └─────────────┘
                  ┌───────────────────┐
                  │   Integration     │  (Mock APIs, test workflows)
                  └───────────────────┘
              ┌─────────────────────────────┐
              │        Unit Tests            │  (85%+ coverage)
              └─────────────────────────────┘
```

### Test Coverage Targets
- **Parser**: 95%+ (critical for correctness)
- **Enrichment**: 90%+ (API mocking)
- **Publishers**: 85%+ (MISP/OpenCTI mocking)
- **Aggregator**: 95%+ (scoring logic critical)
- **Overall**: 85%+

### Test Fixtures
- `tests/fixtures/valid_iocs.txt` - All valid IOC types
- `tests/fixtures/invalid_iocs.txt` - Malformed IOCs
- `tests/fixtures/mixed_iocs.txt` - Mix of valid/invalid
- `tests/fixtures/vt_response_*.json` - VT API mocks
- `tests/fixtures/abuseipdb_response.json` - AIB API mock
- `tests/fixtures/otx_response_*.json` - OTX API mocks

---

## Success Criteria

### MVP (v0.1.0) ✅
- [x] Parse and validate 6 IOC types (IP, domain, URL, MD5, SHA1, SHA256)
- [x] Enrich against VT, AbuseIPDB, OTX
- [x] Post PR comments with enrichment results
- [x] Deploy to MISP and OpenCTI on merge
- [x] 85%+ test coverage (achieved: 96%)
- [x] Full documentation (README, CLAUDE.md, PROJECT_SPEC, WORKFLOW, CHANGELOG)

### Future Enhancements (v0.2.0+)
- [ ] IPv6 support
- [ ] Additional TI sources (Shodan, GreyNoise)
- [ ] Scheduled re-validation of existing IOCs
- [ ] STIX 2.1 input format
- [ ] Batch size limits
- [ ] Incremental enrichment (caching)

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| TI source rate limits hit | High | Medium | Token bucket limiter, daily budget tracking |
| Malformed IOC breaks parser | Medium | Low | Comprehensive validation, catch-all error handling |
| MISP/OpenCTI auth failure | Medium | High | Fail fast, clear error messages, retry logic |
| GitHub Actions timeout | Low | Medium | Batch size limits (future), concurrent enrichment |
| Stale PR enrichment data | Medium | Low | Re-enrich on deploy workflow |

---

## Appendix: IOC Examples

### Valid IOCs
```
192.168.1.1                                      # IP
evil.example.com                                 # Domain
http://malware.site/payload.exe                  # URL
d41d8cd98f00b204e9800998ecf8427e                # MD5
da39a3ee5e6b4b0d3255bfef95601890afd80709        # SHA1
e3b0c44298fc1c149afbf4c8996fb92427ae41e464... # SHA256
```

### Invalid IOCs
```
999.999.999.999                    # Invalid IP octets
invalid domain                     # No TLD
not-a-hash                         # Not hex
abc123                             # Too short for any hash type
```
