# IOC CI/CD Pipeline

**Automated validation, enrichment, and deployment of Indicators of Compromise (IOCs)**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Tests: 160 passed](https://img.shields.io/badge/tests-160%20passed-brightgreen.svg)]()
[![Coverage: 96%](https://img.shields.io/badge/coverage-96%25-brightgreen.svg)]()

---

## 🎯 Overview

This GitHub Action automates the ingestion, validation, enrichment, and deployment of Indicators of Compromise (IOCs). Security analysts commit a plain-text IOC list to the repo, a PR triggers automated enrichment against multiple threat intelligence sources, and merging the PR pushes validated IOCs to MISP and OpenCTI.

### Key Features

- **Auto-detection** of IOC types (IPv4, Domain, URL, MD5, SHA1, SHA256)
- **Multi-source enrichment** via VirusTotal, AbuseIPDB, and OTX AlienVault
- **PR-based review gate** with automated enrichment reports posted as comments
- **Configurable confidence thresholds** with override capability
- **Automated deployment** to MISP and OpenCTI on merge to main
- **Async concurrent enrichment** for high performance
- **Rate limiting** and error handling for TI APIs

---

## 🚀 Quick Start

### Prerequisites

- GitHub repository with Actions enabled
- API keys for:
  - [VirusTotal](https://www.virustotal.com/gui/my-apikey) (free tier: 4 req/min)
  - [AbuseIPDB](https://www.abuseipdb.com/api) (free tier: 1000 req/day)
  - [OTX AlienVault](https://otx.alienvault.com/api) (free tier: 10k req/hour)
- MISP and/or OpenCTI instances (for deployment)

### Workflow Overview

1. **Add IOCs** to `iocs/indicators.txt` (one per line, no prefixes)
2. **Open a PR** - validation runs, enrichment report posted as comment
3. **Review** the enrichment results in the PR comment
4. **Merge** - IOCs are deployed to MISP/OpenCTI automatically
5. **Automatic cleanup**:
   - IOCs appended to `iocs/master-indicators.csv` with metadata
   - `iocs/indicators.txt` automatically cleared for next batch

### Setup

1. **Add GitHub Secrets** (Settings → Secrets and variables → Actions → New repository secret):

   ```
   VT_API_KEY=<your-virustotal-api-key>
   ABUSEIPDB_API_KEY=<your-abuseipdb-api-key>
   OTX_API_KEY=<your-otx-api-key>
   MISP_URL=<your-misp-instance-url>
   MISP_API_KEY=<your-misp-api-key>
   OPENCTI_URL=<your-opencti-instance-url>
   OPENCTI_TOKEN=<your-opencti-token>
   ```

2. **Create a production environment** (Settings → Environments → New environment):
   - Name: `production`
   - Optionally add required reviewers for an additional gate before deployment

3. **Add IOCs to `iocs/indicators.txt`**:

   ```
   # Phishing campaign C2 infrastructure
   185.220.101.34
   evil-login.com
   http://malware.site/payload.exe
   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
   ```

4. **Create a Pull Request** with your IOC changes

5. **Review the enrichment report** posted as a PR comment

6. **Merge the PR** to automatically:
   - Deploy IOCs to MISP and OpenCTI
   - Append IOCs to `iocs/master-indicators.csv` (master inventory)
   - Clear `iocs/indicators.txt` for the next batch

## 📊 Master IOC Inventory

The pipeline maintains a **master inventory** at `iocs/master-indicators.csv` containing all processed IOCs with:

- **IOC Type** (ip, domain, url, hash_md5, hash_sha1, hash_sha256)
- **IOC Value** (the actual indicator)
- **Confidence Score** (0-100 from enrichment)
- **Deployed To** (MISP,OpenCTI or N/A if below threshold)
- **Added Date** (timestamp)
- **Commit SHA** (GitHub commit that added it)

**Example CSV**:
```csv
ioc_type,ioc_value,confidence_score,deployed_to,added_date,commit_sha
domain,evil.com,85.23,MISP,OpenCTI,2026-02-17 14:30:00,abc12345
ip,192.0.2.1,45.67,N/A,2026-02-17 14:30:00,abc12345
```

This provides:
- ✅ **Audit trail** of all IOCs processed
- ✅ **Deduplication** across batches
- ✅ **Historical record** of deployment decisions
- ✅ **Easy export** for analysis or reporting

---

## 📝 IOC Input Format

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

### Supported IOC Types

| Type | Detection | Example |
|------|-----------|---------|
| **IPv4** | `validators.ipv4()` | `192.168.1.1` |
| **Domain** | `validators.domain()` | `evil.example.com` |
| **URL** | `validators.url()` | `http://malware.site/payload.exe` |
| **MD5** | 32 hex chars + `validators.md5()` | `d41d8cd98f00b204e9800998ecf8427e` |
| **SHA1** | 40 hex chars + `validators.sha1()` | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| **SHA256** | 64 hex chars + `validators.sha256()` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

### Rules

- Lines starting with `#` are comments
- Empty lines are ignored
- Case-insensitive deduplication is applied
- Auto-detection order: URL → IP → Hashes → Domain

---

## 🔄 Workflows

### 1. PR Validation (`validate.yml`)

**Trigger**: Pull request opened/updated when `iocs/indicators.txt` changes

**Actions**:
1. Diffs the IOC file against main to extract only **new** IOCs
2. Parses and validates IOC format
3. Enriches each IOC against VirusTotal, AbuseIPDB, and OTX concurrently
4. Computes a weighted confidence score (VT: 0.45, AIB: 0.25, OTX: 0.30)
5. Posts an enrichment report as a PR comment (updates on each push)
6. **Fails** if IOCs are malformed or below the confidence threshold (configurable)

**Example PR Comment**:

```markdown
## IOC Enrichment Report
**Analyzed**: 15 | **Passed**: 12 | **Below threshold**: 2 | **Malformed**: 1

### ⚠️ Malformed IOCs
| Line | Raw Input | Error |
|------|-----------|-------|
| 7 | `999.999.999.999` | Invalid IP address |

### ✅ Passed Validation
<details>
<summary>Click to expand (12 IOCs)</summary>

| IOC | Type | VT | AbuseIPDB | OTX | Confidence | Tags |
|-----|------|----|-----------|-----|------------|------|
| `evil.com` | domain | 85.0 | N/A | 72.0 | 79.8 | malware, c2 |
...
</details>
```

### 2. Deployment (`deploy.yml`)

**Trigger**: Push to `main` when `iocs/indicators.txt` changes

**Actions**:
1. Diffs against the previous commit to find newly merged IOCs
2. Re-enriches IOCs (fresh scores, PR validation may be stale)
3. Filters to IOCs above the confidence threshold
4. Creates a MISP event with all passing IOCs as attributes
5. Creates OpenCTI observables and promotes them to indicators
6. **Appends all IOCs** (passed and failed) to `iocs/master-indicators.csv`
7. **Clears `iocs/indicators.txt`** for the next batch
8. **Commits changes** back to the repo with `[skip ci]`

**Environment**: Uses the `production` GitHub Environment (can add required reviewers)

---

## ⚙️ Configuration

### Required Secrets

| Secret | Description |
|--------|-------------|
| `VT_API_KEY` | VirusTotal API v3 key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API v2 key |
| `OTX_API_KEY` | OTX AlienVault API key |
| `MISP_URL` | MISP instance URL (deploy only) |
| `MISP_API_KEY` | MISP API key (deploy only) |
| `OPENCTI_URL` | OpenCTI instance URL (deploy only) |
| `OPENCTI_TOKEN` | OpenCTI API token (deploy only) |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIDENCE_THRESHOLD` | `70` | Minimum confidence score (0-100) |
| `MISP_VERIFY_SSL` | `true` | Verify MISP TLS certificate |
| `MISP_DISTRIBUTION` | `0` | MISP event distribution (0=org, 1=community, 2=connected, 3=all) |
| `MISP_AUTO_PUBLISH` | `false` | Auto-publish MISP events |
| `WEIGHT_VT` | `0.45` | VirusTotal weight in confidence scoring |
| `WEIGHT_ABUSEIPDB` | `0.25` | AbuseIPDB weight in confidence scoring |
| `WEIGHT_OTX` | `0.30` | OTX weight in confidence scoring |

---

## 🧪 Development

### Local Setup

```bash
# Clone the repository
git clone https://github.com/your-org/ioc-ci-cd.git
cd ioc-ci-cd

# Create virtual environment
python3.12 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"
```

### Run Locally

```bash
# Set API keys
export VT_API_KEY="your-key"
export ABUSEIPDB_API_KEY="your-key"
export OTX_API_KEY="your-key"

# Validate IOCs
python -m src.cli validate iocs/indicators.txt --threshold=70

# The report will be written to /tmp/enrichment_report.md
```

### Run Tests

```bash
# Run all tests with coverage (160 tests, 96% coverage)
pytest tests/ -v --cov=src --cov-report=term

# Run specific test file
pytest tests/test_parser.py -v

# Run linting
ruff check src/ tests/

# Run type checking
mypy src/
```

**Test coverage by module:**

| Module | Tests | Coverage |
|--------|-------|----------|
| Parser | 18 | 100% |
| Models | 8 | 98% |
| Rate limiter | 10 | 100% |
| Enrichment (VT, AbuseIPDB, OTX) | 36 | 96-100% |
| Aggregator | 16 | 100% |
| Publishers (MISP, OpenCTI) | 30 | 97-98% |
| Reporting | 13 | 97% |
| CLI | 21 | 88% |
| **Total** | **160** | **96%** |

### Build Docker Image

```bash
docker build -t ioc-pipeline .
docker run --rm \
  -e VT_API_KEY="..." \
  -e ABUSEIPDB_API_KEY="..." \
  -e OTX_API_KEY="..." \
  ioc-pipeline validate iocs/indicators.txt --threshold=70
```

---

## 📊 Enrichment Sources

### VirusTotal (weight: 0.45)
- **API**: v3 (requires free API key)
- **Rate limit**: 4 requests/minute, 500/day (free tier)
- **Score**: `(malicious + 0.5 * suspicious) / total_engines * 100`
- **Supports**: All IOC types

### AbuseIPDB (weight: 0.25)
- **API**: v2 (requires free API key)
- **Rate limit**: 60 requests/minute, 1000/day (free tier)
- **Score**: `abuseConfidenceScore` (0-100, direct)
- **Supports**: IPv4 addresses only

### OTX AlienVault (weight: 0.30)
- **API**: OTXv2 SDK (requires free API key)
- **Rate limit**: 10,000 requests/hour (free tier)
- **Score**: `min(100, log2(pulse_count + 1) * 15 + 20 if has_malware else 0)`
- **Supports**: All IOC types

### Confidence Aggregation

Weighted average across **available** sources. Weights are renormalized when a source doesn't support the IOC type or errors out.

**Example**: For a domain (AbuseIPDB N/A):
- VT weight becomes: 0.45 / 0.75 = 0.60
- OTX weight becomes: 0.30 / 0.75 = 0.40

---

## 🛡️ Security & Best Practices

### API Key Management
- Store API keys in GitHub Secrets (never commit to repo)
- Rotate keys regularly
- Use separate keys for dev/staging/prod if available

### Threshold Configuration
- Default threshold (70) balances false positives and coverage
- Lower threshold (50-60) for broader coverage, higher risk
- Higher threshold (80-90) for high-confidence IOCs only

### Review Process
- Always review the PR comment before merging
- Investigate IOCs flagged as below-threshold
- Verify malformed IOCs are truly invalid, not parsing errors

### Rate Limiting
- Free tier API limits are enforced via token bucket rate limiters
- For higher volumes, upgrade to paid API tiers and adjust rate limits via environment variables

---

## 📚 Architecture

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
│  │  │ Orchestr.   │                                       │  │
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

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting (`pytest`, `ruff`, `mypy`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

See [CLAUDE.md](CLAUDE.md) for development guidelines and architecture details.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for malware intelligence
- [AbuseIPDB](https://www.abuseipdb.com/) for IP reputation data
- [OTX AlienVault](https://otx.alienvault.com/) for community threat intelligence
- [MISP Project](https://www.misp-project.org/) for the threat sharing platform
- [OpenCTI](https://www.opencti.io/) for the cyber threat intelligence platform

---

## 📞 Support

For issues, questions, or feature requests:
- Open an [issue](https://github.com/your-org/ioc-ci-cd/issues)
- See [CLAUDE.md](CLAUDE.md) for detailed documentation
- Check [PROJECT_SPEC.md](PROJECT_SPEC.md) for product requirements

---

**Built with ❤️ for the security community**
