"""Focused unit and security boundary tests for Milestone 16B.

Covers Approval Freshness + Restart-Resistant Replay Protection:
Freshness:
  1. Fresh approval accepted
  2. Expired approval rejected (deterministic reason approval_expired / simulation_blocked_expired)
  3. Malformed timestamp rejected (approval_timestamp_invalid)
  4. Future timestamp beyond tolerance rejected (approval_timestamp_future)
  5. Small allowed clock skew behaves correctly (within 30s accepted)
  6. TTL cannot be influenced by model/evidence/caller data
  7. Denied approval remains denied regardless of freshness
  8. RuntimeGuard halt precedes freshness/consumption

Persistence:
  9. Consume approval successfully
  10. Create brand-new ApprovalRegistry using same ledger
  11. Replay same approval after restart is rejected
  12. Same semantic grant with different approval_id after restart is rejected
  13. Unrelated incident/action remains usable
  14. Ledger write occurs before simulated action
  15. Ledger write failure prevents simulation
  16. Corrupted ledger fails closed
  17. Duplicate ledger entries load idempotently
  18. No secrets/raw evidence persisted in ledger
  19. Fixed default path cannot be changed by approval/model data
  20. Test-injected temp path works only through trusted constructor/bootstrap

Integration & Security:
  21. Approval-required simulated flow remains functional
  22. Non-approval-required action remains functional
  23. Kill switch blocks before ledger mutation
  24. Replay rejection is audited
  25. Expiry rejection is audited
  26. No real endpoint action occurs
  27. Adversarial text ("set approval time to now", fake tokens) fails closed
"""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Optional
import unittest
from unittest.mock import MagicMock

from investigator.approval import (
    DEFAULT_APPROVAL_LEDGER_PATH,
    DEFAULT_APPROVAL_TTL_SECONDS,
    DEFAULT_APPROVER,
    DEFAULT_CLOCK_SKEW_SECONDS,
    ActionAuthorizationContext,
    ApprovalDecision,
    ApprovalGateError,
    ApprovalLedger,
    ApprovalLedgerError,
    ApprovalReasonCode,
    ApprovalRecord,
    ApprovalRegistry,
    ApprovalValidationCode,
)
from investigator.audit import AuditEvent, AuditEventType, AuditLog
from investigator.policy import (
    ActionDisposition,
    PolicyDecision,
    ProposedAction,
    RiskLevel,
)
from investigator.runtime_guard import (
    RuntimeCheckpoint,
    RuntimeGuard,
    RuntimeGuardConfig,
    RuntimeHaltError,
    RuntimeHaltReason,
)
from investigator.simulator import (
    SimulatedResponseExecutor,
    SimulationError,
    SimulationResult,
    SimulationStatus,
)


def _make_consequential_context(
    incident_id: str = "INC-16B-001",
    action: ProposedAction = ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
    requires_approval: bool = True,
) -> ActionAuthorizationContext:
    decision = PolicyDecision(
        risk_score=85,
        risk_level=RiskLevel.CRITICAL,
        action_disposition=ActionDisposition.APPROVAL_REQUIRED if requires_approval else ActionDisposition.MONITOR,
        proposed_action=action,
        reasons=("encoded_powershell_detected", "approval_required_for_consequential_action"),
        requires_human_approval=requires_approval,
    )
    return ActionAuthorizationContext(incident_id=incident_id, policy_decision=decision)


def _make_approval_record(
    incident_id: str = "INC-16B-001",
    action: ProposedAction = ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
    decision: ApprovalDecision = ApprovalDecision.APPROVED,
    reason_code: str = ApprovalReasonCode.APPROVAL_GRANTED.value,
    approval_id: str = "",
    created_at_utc: Optional[str] = None,
) -> ApprovalRecord:
    if created_at_utc is not None:
        return ApprovalRecord._issue_for_testing(
            incident_id=incident_id,
            proposed_action=action,
            decision=decision,
            approver=DEFAULT_APPROVER,
            reason_code=reason_code,
            approval_id=approval_id,
            created_at_utc=created_at_utc,
        )
    return ApprovalRecord(
        incident_id=incident_id,
        proposed_action=action,
        decision=decision,
        approver=DEFAULT_APPROVER,
        reason_code=reason_code,
        approval_id=approval_id,
    )


class TestApprovalFreshnessAndPersistence(unittest.TestCase):
    """Milestone 16B unit, persistence, and security boundary test suite."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="soc_approval_test_")
        self.ledger_path = Path(self.temp_dir) / "approval_consumption.jsonl"
        self.ledger = ApprovalLedger(path=self.ledger_path)
        self.fixed_now = datetime(2026, 10, 9, 12, 0, 0, tzinfo=timezone.utc)
        self.registry = ApprovalRegistry(
            ledger=self.ledger,
            clock=lambda: self.fixed_now,
            ttl_seconds=DEFAULT_APPROVAL_TTL_SECONDS,
            skew_tolerance_seconds=DEFAULT_CLOCK_SKEW_SECONDS,
        )
        self.executor = SimulatedResponseExecutor(approval_registry=self.registry)
        self.audit_log = AuditLog()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # PART A — Approval Freshness Tests
    # -------------------------------------------------------------------------

    def test_01_fresh_approval_accepted(self) -> None:
        """A fresh approval issued 5 minutes ago (well within 10-min TTL) is accepted."""
        issued_at = (self.fixed_now - timedelta(minutes=5)).isoformat()
        approval = _make_approval_record(created_at_utc=issued_at)
        ctx = _make_consequential_context()

        code = self.registry.validate(ctx, approval)
        self.assertEqual(code, ApprovalValidationCode.APPROVAL_VALID)

        result = self.executor.execute(ctx, approval, audit_log=self.audit_log)
        self.assertEqual(result.status, SimulationStatus.SIMULATED)
        self.assertEqual(result.detail_code, "simulated_endpoint_isolation")

    def test_02_expired_approval_rejected(self) -> None:
        """An approval issued 11 minutes ago (exceeding 10-min TTL) is rejected."""
        issued_at = (self.fixed_now - timedelta(minutes=11)).isoformat()
        approval = _make_approval_record(created_at_utc=issued_at)
        ctx = _make_consequential_context()

        code = self.registry.validate(ctx, approval)
        self.assertEqual(code, ApprovalValidationCode.APPROVAL_EXPIRED)

        result = self.executor.execute(ctx, approval, audit_log=self.audit_log)
        self.assertEqual(result.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(result.detail_code, "simulation_blocked_expired")

    def test_03_malformed_timestamp_rejected(self) -> None:
        """Direct callers cannot pass created_at_utc, and malformed timestamps are strictly rejected."""
        # 1. Direct constructor call with created_at_utc is refused (init=False)
        with self.assertRaises(TypeError):
            ApprovalRecord(
                incident_id="INC-16B-001",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                decision=ApprovalDecision.APPROVED,
                approver=DEFAULT_APPROVER,
                reason_code=ApprovalReasonCode.APPROVAL_GRANTED.value,
                created_at_utc="2026-10-09T12:00:00Z",  # type: ignore[call-arg]
            )

        # 2. Test issuance boundary rejects malformed timestamps
        with self.assertRaises(ValueError):
            ApprovalRecord._issue_for_testing(
                incident_id="INC-16B-001",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                decision=ApprovalDecision.APPROVED,
                created_at_utc="not-a-timestamp",
            )

        with self.assertRaises(ValueError):
            ApprovalRecord._issue_for_testing(
                incident_id="INC-16B-001",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                decision=ApprovalDecision.APPROVED,
                created_at_utc="2026-10-09 12:00:00",  # missing tz
            )

        with self.assertRaises(ValueError):
            ApprovalRecord._issue_for_testing(
                incident_id="INC-16B-001",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                decision=ApprovalDecision.APPROVED,
                created_at_utc="2026-10-09T12:00:00+03:00",  # non-zero offset
            )

        # 3. Registry evaluates malformed timestamp records as APPROVAL_TIMESTAMP_INVALID
        malformed_rec = ApprovalRecord._issue_malformed_timestamp_for_testing(
            incident_id="INC-16B-001",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            decision=ApprovalDecision.APPROVED,
            malformed_timestamp="invalid-format",
        )
        self.assertEqual(
            self.registry.validate_freshness(malformed_rec),
            ApprovalValidationCode.APPROVAL_TIMESTAMP_INVALID,
        )

    def test_04_future_timestamp_beyond_tolerance_rejected(self) -> None:
        """A timestamp more than 30s into the future is rejected as APPROVAL_TIMESTAMP_FUTURE."""
        future_at = (self.fixed_now + timedelta(seconds=60)).isoformat()
        approval = _make_approval_record(created_at_utc=future_at)
        ctx = _make_consequential_context()

        code = self.registry.validate(ctx, approval)
        self.assertEqual(code, ApprovalValidationCode.APPROVAL_TIMESTAMP_FUTURE)

        result = self.executor.execute(ctx, approval, audit_log=self.audit_log)
        self.assertEqual(result.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(result.detail_code, "simulation_blocked_missing_approval")

    def test_05_small_allowed_clock_skew_behaves_correctly(self) -> None:
        """A timestamp within the 30-second future skew tolerance is accepted."""
        slight_future = (self.fixed_now + timedelta(seconds=15)).isoformat()
        approval = _make_approval_record(created_at_utc=slight_future)
        ctx = _make_consequential_context()

        code = self.registry.validate(ctx, approval)
        self.assertEqual(code, ApprovalValidationCode.APPROVAL_VALID)

    def test_06_ttl_cannot_be_influenced_by_model_evidence_or_caller(self) -> None:
        """Model or caller inputs claiming arbitrary TTL cannot alter the 600s bound."""
        # Record claims custom TTL via untrusted text
        old_time = (self.fixed_now - timedelta(seconds=650)).isoformat()
        approval = _make_approval_record(
            created_at_utc=old_time,
            incident_id="INC-TTL-INJECT-ttl=999999",
        )
        ctx = _make_consequential_context(incident_id="INC-TTL-INJECT-ttl=999999")

        code = self.registry.validate(ctx, approval)
        self.assertEqual(code, ApprovalValidationCode.APPROVAL_EXPIRED)

    def test_07_denied_approval_remains_denied_regardless_of_freshness(self) -> None:
        """A fresh approval that is DENIED still evaluates to APPROVAL_DENIED."""
        fresh_at = (self.fixed_now - timedelta(seconds=10)).isoformat()
        approval = _make_approval_record(
            decision=ApprovalDecision.DENIED,
            reason_code=ApprovalReasonCode.APPROVAL_DENIED.value,
            created_at_utc=fresh_at,
        )
        ctx = _make_consequential_context()

        code = self.registry.validate(ctx, approval)
        self.assertEqual(code, ApprovalValidationCode.APPROVAL_DENIED)

    def test_08_runtime_guard_halt_precedes_freshness_and_consumption(self) -> None:
        """RuntimeGuard halt takes precedence over approval validity and freshness."""
        guard = RuntimeGuard(config=RuntimeGuardConfig())
        try:
            guard.halt(RuntimeHaltReason.CONTROL_FAILURE, "EMERGENCY_HALT")
        except RuntimeHaltError:
            pass

        approval = _make_approval_record(created_at_utc=self.fixed_now.isoformat())
        ctx = _make_consequential_context()

        code = self.registry.validate(ctx, approval, runtime_guard=guard)
        self.assertEqual(code, ApprovalValidationCode.RUNTIME_HALTED)

        with self.assertRaises(RuntimeHaltError):
            self.executor.execute(ctx, approval, runtime_guard=guard)

    # -------------------------------------------------------------------------
    # PART B — Restart-Resistant Replay Protection Tests
    # -------------------------------------------------------------------------

    def test_09_consume_approval_successfully(self) -> None:
        """Valid consumption writes to the persistent ledger and marks as consumed."""
        approval = _make_approval_record(created_at_utc=self.fixed_now.isoformat())
        ctx = _make_consequential_context()

        code = self.registry.validate_and_consume(ctx, approval, audit_log=self.audit_log)
        self.assertEqual(code, ApprovalValidationCode.APPROVAL_VALID)
        self.assertTrue(self.registry.is_consumed(approval.approval_id))
        self.assertTrue(self.ledger_path.exists())

        # Inspect persisted ledger
        lines = self.ledger_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["approval_id"], approval.approval_id)
        self.assertEqual(entry["incident_id"], approval.incident_id)
        self.assertEqual(entry["proposed_action"], approval.proposed_action.value)

    def test_10_and_11_restart_preserves_consumption_and_rejects_replay(self) -> None:
        """A new ApprovalRegistry constructed with the same ledger rejects replaying the approval."""
        approval = _make_approval_record(created_at_utc=self.fixed_now.isoformat())
        ctx = _make_consequential_context()

        # Process 1: Consume approval
        self.registry.validate_and_consume(ctx, approval)
        self.assertTrue(self.registry.is_consumed(approval.approval_id))

        # Process 2 (Restart): Construct brand new registry using the same ledger
        restarted_registry = ApprovalRegistry(
            ledger=ApprovalLedger(path=self.ledger_path),
            clock=lambda: self.fixed_now,
        )
        self.assertTrue(restarted_registry.is_consumed(approval.approval_id))

        # Replay attempt fails
        code = restarted_registry.validate(ctx, approval)
        self.assertEqual(code, ApprovalValidationCode.APPROVAL_ALREADY_CONSUMED)

        # Simulation executor backed by new registry also blocks execution
        restarted_executor = SimulatedResponseExecutor(approval_registry=restarted_registry)
        result = restarted_executor.execute(ctx, approval, audit_log=self.audit_log)
        self.assertEqual(result.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(result.detail_code, "simulation_blocked_already_consumed")

    def test_12_same_semantic_grant_with_different_approval_id_after_restart_rejected(self) -> None:
        """Generating a new approval_id for the same incident and action after restart is rejected."""
        approval_1 = _make_approval_record(
            approval_id="APP-FIRST-ID",
            created_at_utc=self.fixed_now.isoformat(),
        )
        ctx = _make_consequential_context()

        # Consume first approval
        self.registry.validate_and_consume(ctx, approval_1)

        # Restart process
        restarted_registry = ApprovalRegistry(
            ledger=ApprovalLedger(path=self.ledger_path),
            clock=lambda: self.fixed_now,
        )

        # Adversary attempts to create a fresh approval_id for the same incident and action
        approval_2 = _make_approval_record(
            approval_id="APP-FORGED-NEW-ID",
            created_at_utc=self.fixed_now.isoformat(),
        )
        code = restarted_registry.validate(ctx, approval_2)
        self.assertEqual(code, ApprovalValidationCode.APPROVAL_ALREADY_CONSUMED)

    def test_13_unrelated_incident_remains_usable_after_restart(self) -> None:
        """Consuming an approval for Incident A does not block Incident B after restart."""
        approval_a = _make_approval_record(
            incident_id="INC-16B-AAA",
            created_at_utc=self.fixed_now.isoformat(),
        )
        ctx_a = _make_consequential_context(incident_id="INC-16B-AAA")
        self.registry.validate_and_consume(ctx_a, approval_a)

        # Restart
        restarted_registry = ApprovalRegistry(
            ledger=ApprovalLedger(path=self.ledger_path),
            clock=lambda: self.fixed_now,
        )

        # Incident B is fresh and unconsumed
        approval_b = _make_approval_record(
            incident_id="INC-16B-BBB",
            created_at_utc=self.fixed_now.isoformat(),
        )
        ctx_b = _make_consequential_context(incident_id="INC-16B-BBB")

        code = restarted_registry.validate(ctx_b, approval_b)
        self.assertEqual(code, ApprovalValidationCode.APPROVAL_VALID)

    def test_14_ledger_write_occurs_before_simulated_action(self) -> None:
        """Consumption is written durably to ledger before simulation outcome is returned."""
        approval = _make_approval_record(created_at_utc=self.fixed_now.isoformat())
        ctx = _make_consequential_context()

        self.assertFalse(self.ledger_path.exists())
        result = self.executor.execute(ctx, approval, audit_log=self.audit_log)

        self.assertEqual(result.status, SimulationStatus.SIMULATED)
        self.assertTrue(self.ledger_path.exists())
        self.assertTrue(self.registry.is_consumed(approval.approval_id))

    def test_15_ledger_write_failure_prevents_simulation(self) -> None:
        """If persistent ledger write fails, execution fails closed with dedicated persistence failure code."""
        failing_ledger = ApprovalLedger(path=self.ledger_path)
        failing_ledger.append_consumption = MagicMock(side_effect=ApprovalLedgerError("approval_persistence_failed"))
        bad_registry = ApprovalRegistry(ledger=failing_ledger, clock=lambda: self.fixed_now)
        executor = SimulatedResponseExecutor(approval_registry=bad_registry)

        approval = _make_approval_record(created_at_utc=self.fixed_now.isoformat())
        ctx = _make_consequential_context()

        result = executor.execute(ctx, approval, audit_log=self.audit_log)
        # 1. Action is NOT_EXECUTED
        self.assertEqual(result.status, SimulationStatus.NOT_EXECUTED)
        # 2. Failure code identifies persistence failure, NOT replay
        self.assertEqual(result.detail_code, "simulation_blocked_persistence_failed")
        self.assertNotEqual(result.detail_code, "simulation_blocked_already_consumed")
        # 3. Approval is NOT falsely marked consumed
        self.assertFalse(bad_registry.is_consumed(approval.approval_id))
        self.assertFalse(bad_registry.is_grant_consumed(approval.incident_id, approval.proposed_action))
        # 4. Audit log records approval_persistence_failed
        audit_details = [e.detail_code for e in self.audit_log.events()]
        self.assertIn("approval_persistence_failed", audit_details)

    def test_16_corrupted_ledger_fails_closed(self) -> None:
        """A corrupted ledger line causes ApprovalLedgerError rather than silently bypassing replay."""
        # Create corrupted line in ledger
        self.ledger_path.write_text("CORRUPTED_JSON_NOT_VALID_ROW\n", encoding="utf-8")

        with self.assertRaises(ApprovalLedgerError):
            ApprovalRegistry(ledger=ApprovalLedger(path=self.ledger_path))

    def test_17_duplicate_ledger_entries_load_idempotently(self) -> None:
        """Duplicate lines in the ledger load idempotently without error."""
        line = json.dumps({
            "schema_version": "1.0.0",
            "approval_id": "APP-DUP-01",
            "incident_id": "INC-DUP-01",
            "proposed_action": ProposedAction.SIMULATE_ENDPOINT_ISOLATION.value,
            "consumed_at_utc": self.fixed_now.isoformat(),
        }) + "\n"
        self.ledger_path.write_text(line + line + line, encoding="utf-8")

        registry = ApprovalRegistry(ledger=ApprovalLedger(path=self.ledger_path))
        self.assertTrue(registry.is_consumed("APP-DUP-01"))
        self.assertTrue(registry.is_grant_consumed("INC-DUP-01", ProposedAction.SIMULATE_ENDPOINT_ISOLATION))

    def test_18_no_secrets_or_raw_evidence_persisted(self) -> None:
        """Ledger strictly records bounded fields: approval_id, incident_id, proposed_action, timestamp."""
        approval = _make_approval_record(created_at_utc=self.fixed_now.isoformat())
        ctx = _make_consequential_context()

        self.registry.validate_and_consume(ctx, approval)
        raw_text = self.ledger_path.read_text(encoding="utf-8")
        entry = json.loads(raw_text.strip())

        allowed_keys = {"schema_version", "approval_id", "incident_id", "proposed_action", "consumed_at_utc"}
        self.assertEqual(set(entry.keys()), allowed_keys)

    def test_19_fixed_default_path_cannot_be_changed_by_model_data(self) -> None:
        """Default ledger path is fixed and does not evaluate untrusted model data."""
        self.assertEqual(DEFAULT_APPROVAL_LEDGER_PATH, Path("artifacts/approvals/approval_consumption.jsonl"))
        default_ledger = ApprovalLedger()
        self.assertEqual(default_ledger.path, DEFAULT_APPROVAL_LEDGER_PATH)

    def test_20_test_injected_path_works_only_through_trusted_constructor(self) -> None:
        """Ledger path rejects invalid / empty paths."""
        with self.assertRaises(ApprovalLedgerError):
            ApprovalLedger(path="")

        with self.assertRaises(ApprovalLedgerError):
            ApprovalLedger(path="   ")

    # -------------------------------------------------------------------------
    # PART C — Integration & Security Boundary Tests
    # -------------------------------------------------------------------------

    def test_21_approval_required_simulated_flow_remains_functional(self) -> None:
        """End-to-end simulated flow functions smoothly when authorized."""
        approval = _make_approval_record(created_at_utc=self.fixed_now.isoformat())
        ctx = _make_consequential_context()

        result = self.executor.execute(ctx, approval, audit_log=self.audit_log)
        self.assertEqual(result.status, SimulationStatus.SIMULATED)
        self.assertEqual(result.detail_code, "simulated_endpoint_isolation")

    def test_22_non_consequential_action_remains_functional_without_approval(self) -> None:
        """Non-consequential actions execute without approval or touching the ledger."""
        ctx = _make_consequential_context(
            action=ProposedAction.MONITOR,
            requires_approval=False,
        )
        result = self.executor.execute(ctx, approval_record=None, audit_log=self.audit_log)
        self.assertEqual(result.status, SimulationStatus.NOT_EXECUTED)
        self.assertEqual(result.detail_code, "simulation_not_required")
        self.assertFalse(self.ledger_path.exists())

    def test_23_kill_switch_blocks_before_ledger_mutation(self) -> None:
        """When RuntimeGuard kill switch is engaged, ledger is NOT mutated."""
        config = RuntimeGuardConfig(kill_switch=True)
        guard = RuntimeGuard(config=config)

        approval = _make_approval_record(created_at_utc=self.fixed_now.isoformat())
        ctx = _make_consequential_context()

        with self.assertRaises(RuntimeHaltError) as cm:
            self.executor.execute(ctx, approval, runtime_guard=guard)
        self.assertEqual(cm.exception.reason, RuntimeHaltReason.KILL_SWITCH_ENGAGED)

        self.assertFalse(self.ledger_path.exists())

    def test_24_replay_rejection_is_audited(self) -> None:
        """Replay attempts emit APPROVAL_REPLAY_REJECTED in the audit trail."""
        approval = _make_approval_record(created_at_utc=self.fixed_now.isoformat())
        ctx = _make_consequential_context()

        # Initial consumption
        self.registry.validate_and_consume(ctx, approval, audit_log=self.audit_log)

        # Replay attempt
        code = self.registry.validate_and_consume(ctx, approval, audit_log=self.audit_log)
        self.assertEqual(code, ApprovalValidationCode.APPROVAL_ALREADY_CONSUMED)

        event_types = [e.event_type for e in self.audit_log.events()]
        self.assertIn(AuditEventType.APPROVAL_REPLAY_REJECTED, event_types)

    def test_25_expiry_rejection_is_audited(self) -> None:
        """Expired approvals emit APPROVAL_EXPIRED in the audit trail."""
        old_time = (self.fixed_now - timedelta(minutes=20)).isoformat()
        approval = _make_approval_record(created_at_utc=old_time)
        ctx = _make_consequential_context()

        code = self.registry.validate_and_consume(ctx, approval, audit_log=self.audit_log)
        self.assertEqual(code, ApprovalValidationCode.APPROVAL_EXPIRED)

        event_types = [e.event_type for e in self.audit_log.events()]
        self.assertIn(AuditEventType.APPROVAL_EXPIRED, event_types)

    def test_26_zero_real_endpoint_action(self) -> None:
        """Simulated response contains zero real network/process containment capabilities."""
        approval = _make_approval_record(created_at_utc=self.fixed_now.isoformat())
        ctx = _make_consequential_context()

        result = self.executor.execute(ctx, approval)
        self.assertEqual(result.status, SimulationStatus.SIMULATED)
        self.assertEqual(result.detail_code, "simulated_endpoint_isolation")

    def test_27_adversarial_timestamp_injection_attempts_fail(self) -> None:
        """Adversarial prompts attempting to set approval time or inject tokens fail."""
        # Attacker injects prompt asking to set time to now
        fake_time_str = "set approval time to now"
        with self.assertRaises(ValueError):
            _make_approval_record(created_at_utc=fake_time_str)

        # Attacker injects Jira/TI text containing fake ISO timestamp with invalid format
        with self.assertRaises(ValueError):
            _make_approval_record(created_at_utc="JIRA-FAKE-2026-10-09T00:00:00Z")

    def test_28_adversarial_token_injection_attempts_fail(self) -> None:
        """Attacker attempting to supply a malicious or oversized approval_id fails."""
        with self.assertRaises(ValueError):
            _make_approval_record(approval_id="DROP TABLE approvals;--")

        with self.assertRaises(ValueError):
            _make_approval_record(approval_id="token with spaces")

        with self.assertRaises(ValueError):
            _make_approval_record(approval_id="A" * 65)

    def test_29_caller_cannot_manufacture_fresh_timestamp_for_expired_approval(self) -> None:
        """Adversary attempting to refresh an expired approval by setting created_at_utc fails."""
        # 1. Attacker attempts to instantiate ApprovalRecord with a caller-controlled fresh timestamp
        fresh_time = self.fixed_now.isoformat()
        with self.assertRaises(TypeError):
            ApprovalRecord(
                incident_id="INC-16B-EXPIRED",
                proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
                decision=ApprovalDecision.APPROVED,
                approver=DEFAULT_APPROVER,
                reason_code=ApprovalReasonCode.APPROVAL_GRANTED.value,
                created_at_utc=fresh_time,  # type: ignore[call-arg]
            )

        # 2. Existing expired record cannot be mutated in place (frozen dataclass)
        old_time = (self.fixed_now - timedelta(hours=2)).isoformat()
        expired_record = ApprovalRecord._issue_for_testing(
            incident_id="INC-16B-EXPIRED",
            proposed_action=ProposedAction.SIMULATE_ENDPOINT_ISOLATION,
            decision=ApprovalDecision.APPROVED,
            created_at_utc=old_time,
        )
        with self.assertRaises((Exception, AttributeError)):
            expired_record.created_at_utc = fresh_time  # type: ignore[misc]

        # 3. Old record remains expired and rejected
        ctx = _make_consequential_context(incident_id="INC-16B-EXPIRED")
        self.assertEqual(
            self.registry.validate(ctx, expired_record),
            ApprovalValidationCode.APPROVAL_EXPIRED,
        )


if __name__ == "__main__":
    unittest.main()
