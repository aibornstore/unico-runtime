# UNICO Runtime — Recovery & Continuity

Global standard: `aibornstore/connect-canon/docs/ARTWEB_PROJECT_RECOVERY_CONTINUITY_STANDARD_V1.md`

No Publisher-specific host/IP/path/credential values belong here unless independently verified for this project.

Required rollout: bind exact runtime host/path/repo; capture branch/HEAD/dirty state; define primary + independent recovery channels; create STATUS/MANIFEST/CONTINUITY/GOLDEN; runtime-certify controlled restart/failover; verify emergency restore.

For long AI/tool operations use bounded checkpoints. On `Resume stream unavailable`, first reconcile live state, then continue only the incomplete step.

Current state: `STANDARD_LINKED_NEEDS_RUNTIME_CERTIFICATION`.
