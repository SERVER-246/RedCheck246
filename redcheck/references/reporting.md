# Reporting, Scoring & Evidence Reference

## Table of Contents

1. [Severity & Confidence Scoring](#severity--confidence-scoring)
2. [Tolerance & Exposure Index](#tolerance--exposure-index)
3. [Report Structure Per Finding](#report-structure-per-finding)
4. [Evidence Collection Standards](#evidence-collection-standards)
5. [Output Deliverables](#output-deliverables)
6. [Engagement Metadata Schema](#engagement-metadata-schema)

---

## Severity & Confidence Scoring

### Severity Levels

| Level | Label | Description |
|-------|-------|-------------|
| 1 | Informational | Observation, no direct risk |
| 2 | Low | Minor issue, limited impact |
| 3 | Medium | Exploitable with conditions |
| 4 | High | Direct exploitable vulnerability |
| 5 | Critical | Immediate breach risk, no conditions |

### Confidence

| Rating | Meaning |
|--------|---------|
| Low | Inferred or theoretical, needs validation |
| Medium | Likely based on evidence, partial confirmation |
| High | Confirmed with reproducible evidence |

Include CVSS v3.1 vector and score where applicable.

---

## Tolerance & Exposure Index

Tolerance Score: 0-100 composite metric.

### Components

| Factor | Weight | Measures |
|--------|--------|----------|
| External exposure | 25% | Internet-facing surface area, open ports, public APIs |
| Privilege escalation potential | 20% | Path from low-priv to root/admin, misconfigurations |
| Data sensitivity | 20% | PII, credentials, financial data, regulated data exposure |
| Hardening maturity | 20% | Patch level, CIS compliance, security headers, TLS config |
| Detection & monitoring strength | 15% | Log coverage, alert latency, SIEM integration, response capability |

### Output

- Numeric score (0-100, lower = more vulnerable)
- Narrative weakest-path analysis describing the most likely breach chain
- Per-component breakdown with justification

---

## Report Structure Per Finding

Each finding uses this structure:

```
### [Finding Title]

**Severity**: [1-5] — [Label] | **CVSS**: [v3.1 vector and score]
**Confidence**: [Low | Medium | High]
**Affected Assets**: [hostname, IP, service, endpoint]

#### Executive Summary
[One-paragraph non-technical description of the issue and its business impact]

#### Technical Details (Sanitized)
[Technical description of the vulnerability, how it was discovered,
and reproduction steps. NO weaponized exploit code.]

#### Root Cause
[Why this vulnerability exists — missing control, misconfiguration, design flaw]

#### Remediation Guidance
[Specific, actionable steps to fix the issue]

#### Validation Steps
[How to verify the fix was applied correctly]

#### Evidence
**Evidence ID**: [EV-YYYYMMDD-NNNN]
[Reference to encrypted evidence bundle]

#### Estimated Fix Effort
[Low | Medium | High] — [Time estimate and resource notes]
```

---

## Evidence Collection Standards (Forensic-Safe)

- UTC timestamps for every action (ISO 8601)
- Immutable logging of tool versions and parameters used
- Sanitized artifact storage (no credentials in cleartext)
- Encrypted evidence vault restricted to sole authorizer
- SHA-256 hash validation for integrity assurance on all artifacts
- Chain-of-custody logging: who accessed, when, why

---

## Output Deliverables

1. **Executive Summary** — Non-technical overview for leadership
2. **Technical Findings Report** — Full per-finding documentation
3. **Prioritized Remediation Plan** — Ranked by risk and effort
4. **Encrypted Evidence Bundle** — All artifacts, encrypted to authorizer's key
5. **Retest Validation Report** — Confirmation of fixes after remediation

---

## Engagement Metadata Schema

```yaml
engagement_id: string          # Unique engagement identifier
client_name: string            # Sole authorizer / project owner
authorized_targets:
  - hostname_or_ip: string
    allowed_tests:
      - recon
      - non-destructive-scan
      - fuzzing
      - config-review
    sensitivity: low|medium|high
rules_of_engagement_link: string   # Path/URL to signed RoE
contact:
  escalation_name: string
  phone: string
  email: string
start_time_utc: ISO8601
end_time_utc: ISO8601
```
