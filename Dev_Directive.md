THIS IS A DIRECTIVE, NOT A PROMPT.

YOU ARE THE PRIMARY DEVELOPMENT ORCHESTRATOR FOR THE CURRENT WORKSPACE.
YOU HAVE FULL READ/WRITE ACCESS TO THE REPOSITORY AND LOCAL GIT.

YOUR MANDATE:

TRANSFORM THIS REPOSITORY INTO A FULLY STRUCTURED, PLUGIN-BASED, POLICY-GATED SECURITY ASSESSMENT FRAMEWORK NAMED "RedCheck".

IMPLEMENT A MODULAR ARCHITECTURE FROM DAY ONE.

NO MONOLITHIC STRUCTURE.

ALL CAPABILITIES MUST BE IMPLEMENTED AS PLUGINS.

ACTIVE MODULES MUST EXIST BUT MUST NOT EXECUTE WITHOUT SIGNED AUTHORIZATION + ACTIVATION CODE.

NOTHING MAY EXECUTE AGAINST ANY TARGET UNTIL:

A SIGNED RoE YAML FILE IS VERIFIED

AN ACTIVATION CODE PROVIDED BY THE USER IS VALIDATED

POLICY ENGINE APPROVES THE ACTION

YOU MUST ASK FOR INPUT WHEN MARKED INPUT_REQUIRED.
DO NOT GUESS.
DO NOT INVENT VALUES.

LOG ALL ACTIONS TO logs/audit.log.

GLOBAL SAFETY GUARDRails (NON-NEGOTIABLE)

NEVER RUN ACTIVE SCANS WITHOUT SIGNED RoE + ACTIVATION CODE.

NEVER OUTPUT EXPLOIT PAYLOADS TO PUBLIC FILES.

NEVER STORE SECRETS IN PLAINTEXT.

ALL ACTIVE MODULES MUST CHECK POLICY ENGINE BEFORE EXECUTION.

IF POLICY VALIDATION FAILS → ABORT AND LOG.

PHASE 1 — ENVIRONMENT VALIDATION

MANDATORY COMMANDS TO RUN AND RECORD OUTPUT:

git rev-parse --abbrev-ref HEAD (or state NO-GIT-REPO)

git rev-parse HEAD (or state NO-GIT-REPO)

git status

python3 --version

pip --version

WRITE outputs into logs/audit.log.

INPUT_REQUIRED:
"Confirm you are operating inside an isolated development VM or devcontainer (yes/no)."

IF answer != yes → HALT.

PHASE 2 — ARCHITECTURE INITIALIZATION

CREATE THE FOLLOWING STRUCTURE IF NOT PRESENT:

RedCheck246/
├── redcheck/
│ ├── core/
│ │ ├── orchestrator.py
│ │ ├── policy_engine.py
│ │ ├── activation_engine.py
│ │ └── audit.py
│ ├── plugins/
│ │ ├── base_plugin.py
│ │ ├── recon/
│ │ ├── sast/
│ │ ├── dast/
│ │ ├── fuzzing/
│ │ └── supply_chain/
│ ├── security/
│ │ ├── crypto.py
│ │ ├── roe_validator.py
│ │ └── signature_verifier.py
│ ├── cli.py
│ └── config.py
├── engagements/
├── logs/
├── tests/
├── docs/
├── scripts/
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml

ALL plugins must inherit from BasePlugin.

PHASE 3 — POLICY GATING ENGINE

IMPLEMENT policy_engine.py with:

validate_roe_signature(path)

validate_activation_code(code)

is_action_allowed(plugin_name, engagement)

ACTIVE plugins must call:

PolicyEngine.authorize(plugin_name, engagement)

IF authorization fails:

Raise PolicyDeniedException

Log to audit

Terminate execution

PHASE 4 — PLUGIN SYSTEM

DEFINE BasePlugin:

name

version

requires_authorization (bool)

execute(context)

All plugins must:

Register via a plugin registry

Declare whether they require authorization

Plugins requiring authorization:

dast

fuzzing

active recon

privilege simulation

Plugins not requiring authorization:

static code analysis

SBOM scan

metadata inspection

PHASE 5 — ACTIVATION ENGINE

ActivationEngine must:

Accept activation code from user input

Hash and compare against secure stored activation hash

Refuse execution if invalid

Log attempts

INPUT_REQUIRED:
"Provide activation code storage method:

environment variable

secure local encrypted file

vault integration"

Wait for selection before implementation.

PHASE 6 — CLI FRAMEWORK

CLI must support:

redcheck init
redcheck recon --dry-run
redcheck run <plugin>
redcheck list-plugins
redcheck verify-roe <file>
redcheck activate

CLI must never default to active execution.

PHASE 7 — ENGAGEMENT SYSTEM

Create engagement metadata structure:

engagement.yaml:

engagement_id

authorizer

signed_roe_path

allowed_tests

activation_required

start_time

end_time

All runs must require engagement context.

PHASE 8 — SECURITY HARDENING

Implement:

Encrypted evidence storage

Audit log immutability (append-only)

Secret detection pre-commit hook

CI test runner (non-destructive only)

MANDATORY COMMANDS:

git grep -n -I -i "SECRET|TOKEN|PASSWORD|KEY"

detect-secrets scan

If any hardcoded secrets found:
Label:
SECURITY RISK — IMMEDIATE ACTION REQUIRED

PHASE 9 — TESTS

Create unit tests for:

policy engine denial

activation validation

plugin registration

signature verification stub

dry-run recon

Must pass pytest before merge.

PHASE 10 — CI INTEGRATION

Create GitHub workflow:

Lint

Tests

Secret scan

Build package

No deployment

PHASE 11 — INPUT CHECKPOINTS

YOU MUST PAUSE AND ASK WHEN:

Activation code storage choice required

RoE path required

Vault configuration required

Branch creation requires confirmation

Any root privilege operation required

PHASE 12 — EXECUTION ORDER

Validate environment

Create branch: dev/redcheck-architecture-bootstrap-<timestamp>

Build folder structure

Implement base plugin framework

Implement policy engine

Implement activation engine

Implement CLI

Write unit tests

Run pytest

Commit

Ask user before push

NON-NEGOTIABLE BEHAVIOR RULES

DO NOT GUESS VALUES

DO NOT SKIP STEPS

DO NOT RUN ACTIVE MODULES

DO NOT PUSH TO REMOTE WITHOUT EXPLICIT CONFIRMATION

DO NOT PROCEED IF RoE IS INVALID

SUCCESS CRITERIA

RedCheck is considered bootstrapped when:

Plugin architecture functional

Policy gating blocks active modules without RoE

Activation code required for active modules

Unit tests pass

CLI operational

CI pipeline created

Audit logging active

FINAL STEP

After completion:

Print absolute repository path

Print current branch

Print last commit hash

Print plugin list

Print policy gating status

END OF DIRECTIVE