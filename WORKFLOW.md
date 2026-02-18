# IOC CI/CD Pipeline - Detailed Workflow

## 📋 Overview

This document describes the complete workflow from IOC submission to deployment and archival.

---

## 🔄 Complete Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ANALYST WORKFLOW                                  │
└─────────────────────────────────────────────────────────────────────────┘

1. Analyst adds IOCs to iocs/indicators.txt
   └─> One per line, no type prefixes
   └─> Example: evil.com, 192.0.2.1, http://malware.site/payload.exe

2. Analyst creates Pull Request
   └─> PR triggers validate.yml workflow

┌─────────────────────────────────────────────────────────────────────────┐
│                    PR VALIDATION WORKFLOW                                │
│                    (.github/workflows/validate.yml)                      │
└─────────────────────────────────────────────────────────────────────────┘

3. Git diff extracts new IOCs
   └─> Only lines added in this PR (not entire file)

4. Parser validates and auto-detects types
   └─> IP, Domain, URL, MD5, SHA1, SHA256
   └─> Malformed IOCs are flagged

5. Enrichment orchestrator launches
   ┌─────────────────┐
   │  For each IOC:  │
   └─────────────────┘
        ├─> Query VirusTotal (async)
        ├─> Query AbuseIPDB (async)
        └─> Query OTX AlienVault (async)
             └─> Rate limiters enforce API limits

6. Confidence aggregator computes score
   └─> Weighted average: VT(0.45) + AIB(0.25) + OTX(0.30)
   └─> Weights renormalized if source unavailable

7. PR comment formatter generates report
   ┌──────────────────────────────────┐
   │  IOC Enrichment Report           │
   ├──────────────────────────────────┤
   │  Analyzed: 15                    │
   │  Passed: 12                      │
   │  Below threshold: 2              │
   │  Malformed: 1                    │
   ├──────────────────────────────────┤
   │  ⚠️  Malformed IOCs (1)          │
   │  ⚠️  Below Threshold (2)         │
   │  ✅ Passed Validation (12)       │
   │  📊 Source Availability          │
   └──────────────────────────────────┘

8. Report posted as PR comment
   └─> Updates on each push (idempotent)

9. Warnings issued if:
   └─> Any IOCs are malformed (reported in PR comment, pipeline continues)
   └─> IOCs below threshold (still recorded, pipeline continues)

10. Analyst reviews report
    └─> Investigates low-confidence IOCs
    └─> Verifies malformed IOCs
    └─> Approves or requests changes

11. PR merged to main
    └─> Triggers deploy.yml workflow

┌─────────────────────────────────────────────────────────────────────────┐
│                    DEPLOYMENT WORKFLOW                                   │
│                    (.github/workflows/deploy.yml)                        │
└─────────────────────────────────────────────────────────────────────────┘

              PHASE 1 — INVENTORY

12. Git diff extracts newly merged IOCs
    └─> Only lines added by this merge commit

13. Enrichment runs
    └─> Fresh scores from all 3 TI sources (or configured subset)
    └─> Malformed IOCs skipped (warned, not fatal)

14. ALL valid IOCs appended to master CSV (last_hunted_date empty)
    ┌─────────────────────────────────────────────────────────────────────────┐
    │  iocs/master-indicators.csv                                              │
    ├─────────────────────────────────────────────────────────────────────────┤
    │  ioc_type,ioc_value,confidence_score,confidence_level,                   │
    │  added_date,last_hunted_date,commit_sha                                  │
    │  domain,evil.com,85.23,high,2026-02-17 14:30:00,,abc12345               │
    │  ip,192.0.2.1,45.67,medium,2026-02-17 14:30:00,,abc12345                │
    │  ip,10.0.0.1,15.00,low,2026-02-17 14:30:00,,abc12345                    │
    └─────────────────────────────────────────────────────────────────────────┘
    └─> ALL valid IOCs appended (low, medium, and high)
    └─> Deduplication prevents re-adding existing IOCs
    └─> Confidence level computed: LOW (<30), MEDIUM (30-69), HIGH (70+)
    └─> last_hunted_date is empty until first hunt run

              PHASE 2 — HUNT

15. Age-based IOC selection
    └─> Reads IOCs from master CSV where added_date >= now - MAX_IOC_AGE_DAYS
    └─> Default window: 30 days
    └─> Each publisher independently filters by configurable min confidence level
    └─> Default: all confidence levels (low+)

16. Splunk hunter runs SPL searches (if IOCs meet level)
    ┌──────────────────────────────────────────────────┐
    │  For each IOC:                                    │
    │  1. Build SPL query per IOC type                  │
    │     IP:     index=main (src_ip="x" OR dest_ip="x")│
    │     Domain: index=main (query="x" OR url="*x*")   │
    │     URL:    index=main url="x"                    │
    │     Hash:   index=main (file_hash="x" OR sha256)  │
    │  2. Submit async search job (POST)                 │
    │  3. Poll until DONE                                │
    │  4. Read results: hit count, timestamps           │
    └──────────────────────────────────────────────────┘
    └─> Failure is non-fatal: pipeline continues

17. Elastic hunter runs _search queries (if IOCs meet level)
    ┌──────────────────────────────────────────────────┐
    │  For each IOC:                                    │
    │  1. Build ECS query per IOC type                  │
    │     IP:     source.ip / destination.ip            │
    │     Domain: dns.question.name / url.domain        │
    │     URL:    url.full                              │
    │     Hash:   file.hash.md5/sha1/sha256             │
    │  2. POST _search with @timestamp range filter     │
    │  3. Parse total hits and sample events            │
    └──────────────────────────────────────────────────┘
    └─> Failure is non-fatal: pipeline continues

18. Hunt results logged to workflow run
    ┌─────────────────────────────────┐
    │  Hunt summary (workflow logs)   │
    ├─────────────────────────────────┤
    │  Splunk: evil.com → 47 hits     │
    │  Splunk: 192.0.2.1 → 0 hits    │
    │  Elastic: evil.com → 12 hits   │
    │  Elastic: 192.0.2.1 → 3 hits  │
    └─────────────────────────────────┘
    └─> Results appear in workflow logs only (not PR comments)

19. Master CSV updated with last_hunted_date
    └─> last_hunted_date set to current UTC timestamp for hunted IOCs

20. indicators.txt cleared
    ┌─────────────────────────────────┐
    │  iocs/indicators.txt             │
    ├─────────────────────────────────┤
    │  # IOC CI/CD Pipeline            │
    │  # Add your IOCs here:           │
    │                                  │
    │  (empty - ready for next batch)  │
    └─────────────────────────────────┘

21. Changes committed back to repo
    └─> Commit message: "chore: clear indicators.txt and update master inventory [skip ci]"
    └─> If publisher failed: warning appended to commit message
    └─> [skip ci] prevents recursive workflow trigger
    └─> Bot user: github-actions[bot]

22. Hunt summary logged
    ┌─────────────────────────────────┐
    │  Hunt complete                   │
    │  IOCs hunted: 15                 │
    │  Splunk hits: 52 total           │
    │  Elastic hits: 18 total          │
    │  Master inventory updated        │
    │  indicators.txt cleared          │
    │  ⚠️  (if applicable)             │
    │  Elastic: connection refused     │
    │  See workflow logs for details   │
    └─────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                        END STATE                                         │
└─────────────────────────────────────────────────────────────────────────┘

Final repository state:
  - indicators.txt: Empty (ready for next batch)
  - master-indicators.csv: Updated with new IOCs (last_hunted_date filled)
  - Splunk: SPL search results logged for IOCs meeting Splunk confidence level
  - Elasticsearch: _search results logged for IOCs meeting Elastic confidence level
  - Git history: Commit with [skip ci] (includes warning if any publisher failed)
```

---

## 📁 File Roles

### `iocs/indicators.txt` (Transient Input)
- **Purpose**: Staging area for new IOCs
- **Lifecycle**:
  1. Analyst adds IOCs
  2. PR validation enriches and reports
  3. Merge triggers deployment
  4. **Automatically cleared** after deployment
- **Format**: Plain text, one IOC per line, no prefixes

### `iocs/master-indicators.csv` (Permanent Inventory)
- **Purpose**: Permanent audit trail of all processed IOCs
- **Lifecycle**: Append-only (never cleared)
- **Updated**: Phase 1 adds rows with empty `last_hunted_date`; Phase 2 fills it in after hunting
- **Deduplication**: Prevents re-adding IOCs already in inventory
- **Format**: CSV with headers
  ```
  ioc_type,ioc_value,confidence_score,confidence_level,added_date,last_hunted_date,commit_sha
  ```
- **Age-based selection**: Phase 2 hunts IOCs where `added_date >= now - MAX_IOC_AGE_DAYS`
- **Confidence levels**: low (<30), medium (30-69), high (70+)

---

## 🔐 Security & Permissions

### Required Permissions

**validate.yml**:
- `contents: read` - Read repo files
- `pull-requests: write` - Post PR comments

**deploy.yml**:
- `contents: write` - Write back to repo (clear indicators.txt, update CSV)
- Requires `production` environment with secrets

### API Keys Required

**Enrichment** (both workflows):
- `VT_API_KEY` - VirusTotal
- `ABUSEIPDB_API_KEY` - AbuseIPDB
- `OTX_API_KEY` - OTX AlienVault

**Hunting** (deploy only):
- `SPLUNK_URL`, `SPLUNK_TOKEN` (if Splunk enabled)
- `ELASTIC_URL`, `ELASTIC_API_KEY` (if Elastic enabled)

---

## 🎛️ Configuration Options

### Confidence Threshold (PR Validation)
- **Variable**: `CONFIDENCE_THRESHOLD`
- **Default**: 70
- **Range**: 0-100
- **Effect**: IOCs below this score are warned about in PR comment (but not blocked)

### Per-Publisher Confidence Levels (Deployment)
- **`SPLUNK_MIN_CONFIDENCE_LEVEL`**: Default `low` — hunts all IOCs in Splunk
- **`ELASTIC_MIN_CONFIDENCE_LEVEL`**: Default `low` — hunts all IOCs in Elasticsearch
- **Valid values**: `low`, `medium`, `high`
- **Levels**: LOW (0-29), MEDIUM (30-69), HIGH (70-100)

### Age-Based IOC Selection
- **`MAX_IOC_AGE_DAYS`**: Default `30` — only hunt IOCs added within this window
- **Effect**: IOCs older than this are skipped in Phase 2 (still in master CSV)

### Override Threshold
- **Input**: `override_threshold` (PR workflow_dispatch only)
- **Default**: false
- **Effect**: When true, suppresses below-threshold warnings

### Modular Source/Publisher Selection
- **`ENRICHMENT_SOURCES`**: Comma-separated list (default: `virustotal,abuseipdb,otx`)
- **`PUBLISHERS`**: Comma-separated list (default: `splunk,elastic`)
- API keys/URLs only required for enabled sources/publishers

### Hunter Options
- `SPLUNK_INDEX` - Index to search (default: `main`)
- `ELASTIC_INDEX` - Index pattern to search (default: `*`)
- `ELASTIC_VERIFY_SSL` - Verify TLS cert (default: `true`)

### Scoring Weights
- `WEIGHT_VT` (default: 0.45)
- `WEIGHT_ABUSEIPDB` (default: 0.25)
- `WEIGHT_OTX` (default: 0.30)

---

## 🔍 Deduplication Strategy

### Within a single PR/batch:
- Parser deduplicates case-insensitively
- Only first occurrence kept
- Duplicates counted in report

### Across batches (master inventory):
- Before appending to CSV, check if `(ioc_type, ioc_value)` already exists
- Skip if found (prevents re-processing)
- Analyst can force re-evaluation by removing from CSV and re-adding

---

## ⚠️ Error Handling

### Validation (PR)
- **Malformed IOCs**: Warning issued, reported in PR comment (pipeline does not fail)
- **TI source failure**: Non-fatal, source marked unavailable
- **Below threshold**: Warning issued, IOCs still recorded (pipeline does not fail)

### Deployment (Merge)
- **Splunk failure**: Non-fatal, warning logged, pipeline continues with Elastic
- **Elastic failure**: Non-fatal, warning logged, pipeline continues
- **Both hunters fail**: Warning embedded in commit message, IOCs remain with empty `last_hunted_date`
- **Hunter errors**: Logged via `::warning::` annotations in workflow run

### Automatic Recovery
- **Re-enrichment on deploy**: Avoids stale data
- **Retry logic**: 3 attempts for enrichment clients with exponential backoff
- **Idempotent operations**: Safe to re-run; `last_hunted_date` updated on success

---

## 📊 Audit Trail

Every IOC in the master inventory includes:

1. **What**: IOC type and value
2. **Score**: Confidence from enrichment (score + level)
3. **When added**: Timestamp of inventory processing
4. **When hunted**: Timestamp of last hunt run (`last_hunted_date`)
5. **Who**: Commit SHA linking to PR/author

This provides complete traceability for compliance and incident response.

---

## 🚀 Best Practices

### For Analysts
1. **Small batches**: Submit 10-50 IOCs per PR for easy review
2. **Descriptive comments**: Use `#` comments to document context
3. **Review enrichment**: Check low-confidence IOCs before merging
4. **Monitor master CSV**: Periodically review for outdated IOCs

### For Security Teams
1. **Set threshold conservatively**: Start at 70, tune based on false positive rate
2. **Review rejected IOCs**: Low-confidence doesn't mean "safe"
3. **Regular audits**: Export master CSV for analysis
4. **Tune weights**: Adjust source weights based on your trust levels

### For Administrators
1. **Rotate API keys**: Regular rotation (quarterly recommended)
2. **Monitor rate limits**: Upgrade API tiers if hitting enrichment limits
3. **Backup master CSV**: Part of repo, but consider external backup
4. **Review hunt results**: Check workflow logs after each deploy for hit counts
