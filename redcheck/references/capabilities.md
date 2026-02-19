# RedCheck Capabilities Reference

## Table of Contents

1. [Reconnaissance & Asset Discovery](#1-reconnaissance--asset-discovery)
2. [Threat Modeling](#2-threat-modeling)
3. [Automated Scanning](#3-automated-scanning-controlled)
4. [Configuration & Hardening Review](#4-configuration--hardening-review)
5. [Static Analysis (SAST)](#5-static-analysis-sast)
6. [Dynamic Analysis (DAST)](#6-dynamic-analysis-dast--controlled)
7. [Robustness & Fuzz Testing](#7-robustness--fuzz-testing)
8. [CI/CD & Supply Chain Audit](#8-cicd--supply-chain-audit)
9. [Logging & Detection Evaluation](#9-logging--detection-evaluation)
10. [Reporting & Risk Scoring](#10-reporting--risk-scoring)

---

## 1. Reconnaissance & Asset Discovery

- Passive exposure mapping (DNS, WHOIS, certificate transparency, OSINT)
- Certificate and metadata inspection
- Technology stack fingerprinting (non-invasive: HTTP headers, response patterns)
- Asset correlation across repositories and infrastructure metadata
- Subdomain enumeration, port/service mapping (nmap/masscan in non-intrusive mode)

**Tools**: nmap (safe scripts), masscan (rate-limited), openssl s_client, dig, whois, theHarvester

## 2. Threat Modeling

- Automated STRIDE mapping per asset/service
- ATT&CK-style adversary path simulation (conceptual modeling, not exploit execution)
- Attack surface matrix generation linking assets to threat vectors
- Identify trust boundaries, data flows, and entry points

**Output**: Threat model document (Markdown/JSON), attack surface matrix

## 3. Automated Scanning (Controlled)

- Safe service discovery (TCP SYN, version detection)
- Known vulnerability exposure detection via CVE mapping
- Dependency risk analysis and SBOM inspection
- Banner grabbing and default-credential checks (non-destructive)

**Tools**: nmap, nuclei (safe templates), trivy, grype, syft

## 4. Configuration & Hardening Review

- OS and service baseline comparison (CIS benchmarks)
- Container and runtime configuration review (Docker/Podman)
- Permission boundary analysis (sudo, capabilities, SUID/SGID)
- TLS/SSL configuration audit
- Firewall rule analysis

**Tools**: lynis, docker-bench-security, custom scripts

## 5. Static Analysis (SAST)

- Secret detection (API keys, tokens, passwords in source)
- Insecure pattern identification (SQL injection, XSS, path traversal patterns)
- Weak cryptographic implementation review
- Dependency vulnerability mapping (lock files, manifests)
- License compliance scanning

**Tools**: semgrep, trufflehog, gitleaks, bandit (Python), custom regex patterns

## 6. Dynamic Analysis (DAST — Controlled)

- Authentication flow validation (login bypass, token handling)
- Authorization boundary verification (IDOR, privilege escalation)
- Session management analysis (fixation, hijacking, expiry)
- Input validation and error-handling inspection
- Rate-limit tolerance measurement (destructive only when explicitly tasked)
- CORS, CSP, and security header validation

**Tools**: custom HTTP scripts, nuclei, httpx, curl-based probes

**Requires**: Active Testing mode authorization in RoE

## 7. Robustness & Fuzz Testing

**Authorized isolated/staging environments ONLY.**

- Structured fuzz campaigns against API endpoints and parsers
- Crash detection and stack trace capture
- Stability tolerance measurement under load
- Protocol-level fuzzing (HTTP, gRPC, WebSocket)

**Tools**: custom fuzzers, radamsa, boofuzz

**Requires**: Explicit destructive-testing authorization in RoE

## 8. CI/CD & Supply Chain Audit

- Pipeline permission analysis (over-privileged runners, shared secrets)
- Artifact trust chain validation (signing, provenance)
- Secret exposure scanning in CI logs and configs
- Build environment hardening review
- Dependency confusion and typosquatting checks

**Tools**: custom scripts, trivy, syft, pipeline config analysis

## 9. Logging & Detection Evaluation

**Goal**: Assess defensive visibility WITHOUT triggering presence detection.

- Determine whether simulated attacks generate logs
- Measure alerting coverage (which techniques trigger alerts)
- Evaluate detection latency (time-to-alert)
- Identify blind spots in monitoring coverage
- Review log forwarding integrity

**Method**: Controlled test actions with parallel log monitoring

## 10. Reporting & Risk Scoring

- Executive summary generation (non-technical audience)
- Technical findings documentation with evidence IDs
- CVSS v3.1 mapping per finding
- Custom Tolerance Score calculation (0-100)
- Prioritized remediation plan with effort estimates
- Structured JSON/Markdown export for automation ingestion
