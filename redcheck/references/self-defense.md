# Self-Defense & Anti-Retracing Architecture

## Table of Contents

1. [Core Defensive Principles](#core-defensive-principles)
2. [Anomaly Detection & Shutdown Logic](#anomaly-detection--shutdown-logic)
3. [Anti-Bait Safeguards](#anti-bait-safeguards)
4. [Containment Mode Procedures](#containment-mode-procedures)

---

## Core Defensive Principles

These mechanisms are defensive — focused on containment and isolation.

### Zero Inbound Exposure
Never expose listening services to targets. All testing sessions are outbound-initiated and state-controlled. No reverse shells, no callback listeners, no open ports.

### Ephemeral Execution Environments
Execute engagements inside isolated, disposable containers or VMs. Upon completion (or anomaly detection), destroy the environment completely:

```bash
# Example: spin up disposable container for engagement
docker run --rm --network=redcheck-isolated \
  --read-only --tmpfs /tmp \
  --name "engagement-${ENGAGEMENT_ID}" \
  redcheck-runner:latest

# On completion or anomaly: container auto-destroys (--rm)
```

### Network Segmentation
Run within strictly segmented infrastructure controlled by the sole authorizer. Use dedicated VLANs or network namespaces.

### No Persistent Identifiers
Engagement sessions avoid embedding static identifiers (MAC, hostname patterns, User-Agent strings) that could allow fingerprinting across assessments. Rotate per engagement.

### Strict Egress Control
Only required outbound traffic is permitted during testing. Use firewall rules to whitelist only in-scope targets:

```bash
# Allow only scoped targets
iptables -A OUTPUT -d $TARGET_CIDR -j ACCEPT
iptables -A OUTPUT -d $LOGGING_SERVER -j ACCEPT
iptables -A OUTPUT -j DROP
```

### Evidence Encryption
All artifacts encrypted at rest (GPG/age) and in transit (TLS 1.3+ / WireGuard).

---

## Anomaly Detection & Shutdown Logic

Continuously monitor for:

| Signal | Indicator | Response |
|--------|-----------|----------|
| Inbound scanning | Unexpected SYN/probes to agent host | Throttle + alert |
| Honeypot indicators | Fake services, implausible banners, tarpit behavior | Pause + isolate |
| Timing anomalies | Abnormal response delays suggesting adversarial monitoring | Reduce activity |
| Fingerprinting attempts | Probes targeting agent OS/tool versions | Isolate + notify |
| Counter-operation signs | Active recon against agent infrastructure | Emergency shutdown |

### Shutdown Sequence

1. Immediately throttle all testing activity
2. Snapshot and encrypt current evidence
3. Isolate the execution environment (network disconnect)
4. Notify sole authorizer via configured contact method
5. If risk persists: destroy environment and terminate all active sessions
6. Leave zero operational breadcrumbs

---

## Anti-Bait Safeguards

- Refuse interaction with suspicious unsolicited inbound connections
- Never download or execute unverified external binaries from target systems
- Block any target-initiated attempt to coerce outbound connections beyond scope
- Validate scope before interacting with any discovered endpoint
- Never follow redirects to out-of-scope destinations

These measures prevent the agent from becoming a pivot point or being weaponized by adversarial infrastructure.

---

## Containment Mode Procedures

When Defensive Containment Mode activates:

1. Reduce all network activity to zero
2. Snapshot evidence and session state
3. Sever all connections to target infrastructure
4. Encrypt and seal all artifacts
5. Notify authorizer with anomaly details
6. Await authorizer decision: resume, abort, or investigate
7. If no response within configured timeout: full environment destruction
8. Ensure complete trace elimination — no logs, no artifacts, no network state remains on any external system
