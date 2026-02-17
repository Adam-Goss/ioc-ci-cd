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
    └─> Fresh scores from all 3 TI sources
    └─> Malformed IOCs skipped (warned, not fatal)

14. ALL valid IOCs appended to master CSV as "pending"
    ┌───────────────────────────────────────────────────────────────────────┐
    │  iocs/master-indicators.csv                                            │
    ├───────────────────────────────────────────────────────────────────────┤
    │  ioc_type,ioc_value,confidence_score,confidence_level,status,          │
    │  deployed_to,added_date,commit_sha                                     │
    │  domain,evil.com,85.23,high,pending,N/A,2026-02-17 14:30:00,abc12345  │
    │  ip,192.0.2.1,45.67,medium,pending,N/A,2026-02-17 14:30:00,abc12345   │
    │  ip,10.0.0.1,15.00,low,pending,N/A,2026-02-17 14:30:00,abc12345       │
    └───────────────────────────────────────────────────────────────────────┘
    └─> ALL valid IOCs appended (low, medium, and high)
    └─> Deduplication prevents re-adding existing IOCs
    └─> Confidence level computed: LOW (<30), MEDIUM (30-69), HIGH (70+)
    └─> deployed_to = "N/A" initially, status = "pending"

              PHASE 2 — DEPLOY

15. Per-publisher confidence filtering
    └─> Each publisher independently filters by configurable min level
    └─> MISP: deploys medium + high IOCs (default)
    └─> OpenCTI: deploys only high IOCs (default)
    └─> Configurable via MISP_MIN_CONFIDENCE_LEVEL / OPENCTI_MIN_CONFIDENCE_LEVEL

16. MISP publisher creates event (if IOCs meet level)
    ┌─────────────────────────────────┐
    │  MISP Event                      │
    ├─────────────────────────────────┤
    │  Title: IOC Pipeline Import -   │
    │         2026-02-17 - abc12345    │
    │  Distribution: Org only (0)      │
    │  TLP: amber                      │
    ├─────────────────────────────────┤
    │  Attributes:                     │
    │  - ip-dst: 192.0.2.1            │
    │  - domain: evil.com             │
    │  - url: http://malware.site/... │
    │  - sha256: e3b0c442...          │
    │  Each tagged with confidence    │
    └─────────────────────────────────┘
    └─> Failure is non-fatal: pipeline continues

17. OpenCTI publisher creates observables (if IOCs meet level)
    ┌─────────────────────────────────┐
    │  For each IOC:                   │
    │  1. Create STIX Observable (SCO) │
    │  2. Set x_opencti_score          │
    │  3. Promote to Indicator         │
    │  4. Add labels from enrichment   │
    └─────────────────────────────────┘
    └─> Failure is non-fatal: pipeline continues

18. Master CSV updated with deployment status
    └─> status: "pending" → "deployed"
    └─> deployed_to: "MISP", "OpenCTI", "MISP,OpenCTI", or "N/A" (if no publisher succeeded)

19. indicators.txt cleared
    ┌─────────────────────────────────┐
    │  iocs/indicators.txt             │
    ├─────────────────────────────────┤
    │  # IOC CI/CD Pipeline            │
    │  # Add your IOCs here:           │
    │                                  │
    │  (empty - ready for next batch)  │
    └─────────────────────────────────┘

20. Changes committed back to repo
    └─> Commit message: "chore: clear indicators.txt and update master inventory [skip ci]"
    └─> If publisher failed: warning appended to commit message
    └─> [skip ci] prevents recursive workflow trigger
    └─> Bot user: github-actions[bot]

21. Deployment summary logged
    ┌─────────────────────────────────┐
    │  ✅ Deployment complete          │
    │  IOCs processed: 15              │
    │  Master inventory updated        │
    │  indicators.txt cleared          │
    │  ⚠️  (if applicable)             │
    │  MISP: failed                    │
    │  See commit message for details  │
    └─────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                        END STATE                                         │
└─────────────────────────────────────────────────────────────────────────┘

Final repository state:
  - indicators.txt: Empty (ready for next batch)
  - master-indicators.csv: Updated with new IOCs (status=deployed, deployed_to filled)
  - MISP: Event created with IOCs meeting MISP confidence level
  - OpenCTI: Observables/indicators created for IOCs meeting OpenCTI confidence level
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
- **Updated**: Phase 1 adds rows as `pending`, Phase 2 marks them `deployed`
- **Deduplication**: Prevents re-adding IOCs already in inventory
- **Format**: CSV with headers
  ```
  ioc_type,ioc_value,confidence_score,confidence_level,status,deployed_to,added_date,commit_sha
  ```
- **Status lifecycle**: `pending` (after inventory) → `deployed` (after publish)
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

**Publishing** (deploy only):
- `MISP_URL`, `MISP_API_KEY`
- `OPENCTI_URL`, `OPENCTI_TOKEN`

---

## 🎛️ Configuration Options

### Confidence Threshold (PR Validation)
- **Variable**: `CONFIDENCE_THRESHOLD`
- **Default**: 70
- **Range**: 0-100
- **Effect**: IOCs below this score are warned about in PR comment (but not blocked)

### Per-Publisher Confidence Levels (Deployment)
- **`MISP_MIN_CONFIDENCE_LEVEL`**: Default `medium` — deploys medium + high IOCs to MISP
- **`OPENCTI_MIN_CONFIDENCE_LEVEL`**: Default `high` — deploys only high confidence IOCs to OpenCTI
- **Valid values**: `low`, `medium`, `high`
- **Levels**: LOW (0-29), MEDIUM (30-69), HIGH (70-100)

### Override Threshold
- **Input**: `override_threshold` (PR workflow_dispatch only)
- **Default**: false
- **Effect**: When true, suppresses below-threshold warnings

### Publisher Options
- `MISP_DISTRIBUTION` - Event sharing level (0-3)
- `MISP_AUTO_PUBLISH` - Auto-publish events (true/false)
- `MISP_VERIFY_SSL` - Verify TLS cert (true/false)

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
- **MISP failure**: Non-fatal, warning logged, pipeline continues with OpenCTI
- **OpenCTI failure**: Non-fatal, warning logged, pipeline continues
- **Both publishers fail**: Warning embedded in commit message, IOCs remain as `pending` in CSV
- **Publisher errors**: Logged via `::warning::` annotations, captured in `deploy_warnings.txt` (transient file, not committed)

### Automatic Recovery
- **Re-enrichment on deploy**: Avoids stale data
- **Retry logic**: 3 attempts for MISP/OpenCTI with exponential backoff
- **Idempotent operations**: Safe to re-run

---

## 📊 Audit Trail

Every IOC in the master inventory includes:

1. **What**: IOC type and value
2. **Score**: Confidence from enrichment
3. **Action**: Deployed or not (and where)
4. **When**: Timestamp of processing
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
2. **Monitor rate limits**: Upgrade API tiers if hitting limits
3. **Backup master CSV**: Part of repo, but consider external backup
4. **Review MISP/OpenCTI events**: Ensure proper distribution settings
