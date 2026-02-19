# RedCheck246

**Policy-gated, plugin-based security assessment framework.**

> All active operations require a validated Rules of Engagement (RoE) document and a verified activation code. No exceptions.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Set activation code
redcheck activate --set

# Initialize engagement
redcheck init my-engagement

# Edit the RoE template
nano my-engagement/roe.yaml

# Validate RoE
redcheck verify-roe my-engagement/roe.yaml

# Dry-run recon
redcheck recon --roe my-engagement/roe.yaml --dry-run

# List plugins
redcheck list-plugins

# Check status
redcheck status
```

## Architecture

```
redcheck/
├── core/
│   ├── audit.py              # Hash-chained append-only audit log
│   ├── orchestrator.py        # Engagement lifecycle coordinator
│   ├── policy_engine.py       # Central policy gate
│   └── activation_engine.py   # Activation code management
├── plugins/
│   ├── base_plugin.py         # BasePlugin ABC + PluginRegistry
│   ├── recon/                 # Passive reconnaissance
│   ├── sast/                  # Static analysis
│   ├── dast/                  # Dynamic analysis
│   ├── fuzzing/               # Protocol fuzzing
│   └── supply_chain/          # Dependency auditing
├── security/
│   ├── crypto.py              # AES-256-GCM evidence encryption
│   ├── roe_validator.py       # RoE structural validation
│   └── signature_verifier.py  # HMAC-SHA256 document signing
├── cli.py                     # CLI entry point
└── config.py                  # Central configuration
```

## Policy Model

1. **RoE Validation** — Every engagement requires a signed YAML RoE document
2. **Activation Code** — SHA-512 salted hash stored in secure local encrypted file
3. **Plugin Authorization** — Orchestrator calls `PolicyEngine.authorize()` before any plugin execution
4. **Audit Trail** — Hash-chained, append-only log of all actions

## Testing

```bash
pytest --cov=redcheck tests/
```

## License

Proprietary — SERVER-246
