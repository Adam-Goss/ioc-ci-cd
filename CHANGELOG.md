# Changelog

All notable changes to the IOC CI/CD Pipeline project will be documented in this file.

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
