/**
 * architecture.md §11.2.1 canonical `receipt/v1` example, verbatim.
 * Digests/commits/timestamps are format placeholders (the document says so)
 * and therefore are NOT valid external trust evidence. This fixture exists to
 * prove the strict protocol schema stays one-to-one with the architecture
 * example (structural validation only; digest recomputation is covered in
 * receipt.test.js with a locally signed fixture).
 */
export const CANONICAL_RECEIPT_EXAMPLE = Object.freeze({
  "receipt_schema_version": "receipt/v1",
  "run_id": "run-20261016-001",
  "plan_id": "plan-sha256:6666666666666666666666666666666666666666666666666666666666666666",
  "scenario_ref": {
    "id": "plugin-baseline",
    "version": "1.0.0",
    "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
  },
  "profile_ref": {
    "id": "smoke",
    "version": "1.0.0",
    "digest": "sha256:8888888888888888888888888888888888888888888888888888888888888888"
  },
  "trust_scope": "local-only",
  "market_eligible": false,
  "run_status": "completed",
  "target_ref": {
    "kind": "api",
    "owner_put_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    "origin": "http://127.0.0.1:4001"
  },
  "provenance": {
    "put_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    "dsh_commit": "0123456789abcdef0123456789abcdef01234567",
    "cordis_version": "1.0.0",
    "adapter_ref": "local-worker-json@1.0.0",
    "tool_refs": [
      {
        "tool_id": "example.api-contract",
        "version": "1.0.0",
        "artifact_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
      }
    ],
    "assertion_refs": [
      "assert/login-contract@1.0.0"
    ],
    "policy_ref": {
      "id": "gate-policy",
      "version": "1.0.0",
      "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "environment_fingerprint": "sha256:4444444444444444444444444444444444444444444444444444444444444444"
  },
  "plan_candidate_ref": {
    "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "baseline_test_ids": [
      "contract.login.schema"
    ],
    "required_test_ids": [
      "contract.login.schema"
    ]
  },
  "plan_resolution": [
    {
      "test_id": "contract.login.schema",
      "classification": "required"
    }
  ],
  "reconciliation": {
    "expected": [
      "contract.login.schema"
    ],
    "executed": [
      "contract.login.schema"
    ],
    "missing": [],
    "waived": []
  },
  "test_cases": [
    {
      "test_id": "contract.login.schema",
      "dimensions": {
        "test_level": "component-integration",
        "test_type": [
          "functional"
        ],
        "test_technique": [
          "contract"
        ],
        "trigger": "manual",
        "suite_profile": "smoke",
        "target_kind": "api",
        "execution_mode": "mock",
        "repeatability": "environment-bound",
        "evidence_kind": [
          "assertion",
          "artifact"
        ]
      },
      "attempts": [
        {
          "attempt": 1,
          "admission_status": "accepted",
          "execution_status": "completed",
          "invocation_status": "started",
          "started_at": "2026-10-16T04:29:01Z",
          "ended_at": "2026-10-16T04:29:03Z",
          "verdict": "pass",
          "observation_refs": [
            "obs-001"
          ]
        }
      ],
      "verdict": "pass",
      "criteria_ref": "assert/login-contract@1.0.0",
      "reason_codes": []
    }
  ],
  "observations": [
    {
      "observation_id": "obs-001",
      "schema_ref": "urn:example:tool:api-contract:observation:v1",
      "value": {
        "status_code": 200,
        "body": {
          "user_id": "fixture-user-001"
        }
      },
      "source": "worker",
      "limitations": [
        "controlled-fixture"
      ]
    }
  ],
  "artifacts": [
    {
      "kind": "log",
      "digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
      "size_bytes": 412
    }
  ],
  "gate_decision": "pass",
  "limitations": [
    "mock-target",
    "l1-local-only"
  ],
  "integrity": {
    "record_digest": "sha256:9999999999999999999999999999999999999999999999999999999999999999",
    "signed": false
  }
})
