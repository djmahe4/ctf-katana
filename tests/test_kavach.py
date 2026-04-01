"""
Kavach Integration Tests

Comprehensive test suite for Kavach AI Firewall components:
- Core components (PIISanitizer, PhantomWorkspace, AuditLedger, etc.)
- Monitoring (AutoEnforcer, TripwireMonitor, LoopDetector, etc.)
- Wrapper skill (KavachWrapperSkill)
- Enhanced audit system
"""

import pytest
import tempfile
import time
import os
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

# Import Kavach components
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skills.firewall.kavach import (
    KavachWrapper,
    SecurityPolicy,
    PhantomWorkspace,
    AuditLedger,
    PIISanitizer,
)
from skills.firewall.kavach.monitor import (
    AutoEnforcer,
    TripwireMonitor,
    LoopDetector,
    FileWatcher,
    ProcessMonitor,
)
from skills.firewall.kavach.exceptions import (
    KavachSecurityViolation,
    PhantomWorkspaceError,
    PIIDetectionError,
    TripwireTriggered,
    ExecutionTimeoutError,
    ProcessLimitExceeded,
)
from skills.firewall.kavach.audit import (
    EnhancedAuditLedger,
    AuditStatistics,
    NotificationConfig,
)
from skills.firewall.kavach.wrapper.run import KavachWrapperSkill, run


class TestSecurityPolicy:
    """Test SecurityPolicy configuration."""
    
    def test_default_strict_policy(self):
        """Test strict security policy preset."""
        policy = SecurityPolicy.default_strict()
        
        assert policy.allow_network == False
        assert policy.max_child_processes == 3
        assert policy.execution_timeout == 60
        assert policy.sanitize_pii == True
        assert policy.enable_tripwires == True
        assert policy.enable_phantom_workspace == True
    
    def test_default_standard_policy(self):
        """Test standard security policy preset."""
        policy = SecurityPolicy.default_standard()
        
        assert policy.allow_network == True
        assert policy.max_child_processes == 10
        assert policy.execution_timeout == 300
        assert policy.sanitize_pii == True
    
    def test_default_permissive_policy(self):
        """Test permissive security policy preset."""
        policy = SecurityPolicy.default_permissive()
        
        assert policy.allow_network == True
        assert policy.sanitize_pii == False
        assert policy.enable_tripwires == False
        assert policy.enable_phantom_workspace == False


class TestPIISanitizer:
    """Test PII detection and sanitization."""
    
    def test_detect_openai_key(self):
        """Test OpenAI API key detection."""
        sanitizer = PIISanitizer()
        
        text = "My API key is: sk-1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        detections = sanitizer.scan_text(text)
        
        assert len(detections) == 1
        assert detections[0]["type"] == "openai_key"
    
    def test_detect_email(self):
        """Test email address detection."""
        sanitizer = PIISanitizer()
        
        text = "Contact me at user@example.com"
        detections = sanitizer.scan_text(text)
        
        assert len(detections) == 1
        assert detections[0]["type"] == "email"
        assert detections[0]["value"] == "user@example.com"
    
    def test_detect_credit_card(self):
        """Test credit card detection."""
        sanitizer = PIISanitizer()
        
        text = "Card: 4532-1234-5678-9010"
        detections = sanitizer.scan_text(text)
        
        assert len(detections) == 1
        assert detections[0]["type"] == "credit_card"
    
    def test_sanitize_openai_key(self):
        """Test OpenAI key sanitization."""
        sanitizer = PIISanitizer()
        
        text = "Key: sk-1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        sanitized, detections = sanitizer.sanitize(text)
        
        # The key should be partially redacted (prefix visible for debugging)
        assert "sk-12345" in sanitized  # First few chars visible
        assert "*" in sanitized  # Should have redaction
        assert len(detections) == 1
    
    def test_sanitize_email(self):
        """Test email sanitization."""
        sanitizer = PIISanitizer()
        
        text = "Email: user@example.com"
        sanitized, detections = sanitizer.sanitize(text)
        
        assert "@example.com" in sanitized  # Domain visible
        assert "user" not in sanitized.replace("@example.com", "")  # Username redacted
    
    def test_entropy_calculation(self):
        """Test Shannon entropy calculation."""
        sanitizer = PIISanitizer()
        
        low_entropy = "aaaaaaa"
        high_entropy = "aB3$xK9"
        
        assert sanitizer.calculate_entropy(low_entropy) < 2.0
        assert sanitizer.calculate_entropy(high_entropy) > 2.5
    
    def test_get_detection_summary(self):
        """Test detection summary aggregation."""
        sanitizer = PIISanitizer()
        
        text = """
        Key: sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGH
        Email: user@example.com
        Another key: sk-ZYXWVUTSRQPONMLKJIHGFEDCBA0987654321ZYXWVU
        """
        
        sanitizer.scan_text(text)
        summary = sanitizer.get_detection_summary()
        
        assert summary["openai_key"] == 2
        assert summary["email"] == 1


class TestPhantomWorkspace:
    """Test phantom workspace operations."""
    
    def test_phantom_workspace_creation(self):
        """Test phantom workspace initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            phantom = PhantomWorkspace(workspace)
            
            assert phantom.phantom_root.exists()
            assert phantom.phantom_root.name == ".kavach_phantom"
    
    def test_intercept_write(self):
        """Test write operation interception."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            phantom = PhantomWorkspace(workspace)
            
            target = workspace / "test.txt"
            content = b"test data"
            
            phantom_path = phantom.intercept_write(target, content)
            
            assert phantom_path.exists()
            assert phantom_path.read_bytes() == content
            assert not target.exists()  # Original not written
    
    def test_snapshot_and_rollback(self):
        """Test file snapshot and rollback."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            phantom = PhantomWorkspace(workspace)
            
            # Create original file
            target = workspace / "original.txt"
            target.write_text("original content")
            
            # Snapshot
            phantom.snapshot_file(target)
            
            # Modify file
            target.write_text("modified content")
            
            # Rollback
            success = phantom.rollback_file(target)
            
            assert success == True
            assert target.read_text() == "original content"
    
    def test_commit_changes(self):
        """Test committing phantom changes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            phantom = PhantomWorkspace(workspace)
            
            target = workspace / "test.txt"
            content = b"committed data"
            
            # Intercept write
            phantom.intercept_write(target, content)
            
            # Commit
            phantom.commit_changes()
            
            # Original should now exist
            assert target.exists()
            assert target.read_bytes() == content


class TestAuditLedger:
    """Test audit logging."""
    
    def test_log_event(self):
        """Test event logging."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = Path(tmpdir) / "audit.jsonl"
            ledger = AuditLedger(ledger_path)
            
            event_hash = ledger.log_event(
                event_type="test_event",
                skill_name="test_skill",
                severity="INFO",
                details={"key": "value"},
            )
            
            assert isinstance(event_hash, str)
            assert len(event_hash) == 64  # SHA-256 hash
            assert ledger_path.exists()
    
    def test_verify_integrity(self):
        """Test integrity verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = Path(tmpdir) / "audit.jsonl"
            ledger = AuditLedger(ledger_path)
            
            # Log some events
            for i in range(5):
                ledger.log_event(
                    event_type=f"event_{i}",
                    skill_name="test_skill",
                    severity="INFO",
                    details={},
                )
            
            # Verify integrity
            is_valid, errors = ledger.verify_integrity()
            
            assert is_valid == True
            assert len(errors) == 0
    
    def test_query_events(self):
        """Test event querying."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = Path(tmpdir) / "audit.jsonl"
            ledger = AuditLedger(ledger_path)
            
            # Log events
            ledger.log_event("event1", "skill1", "INFO", {})
            ledger.log_event("event2", "skill2", "CRITICAL", {})
            ledger.log_event("event1", "skill1", "HIGH", {})
            
            # Query by event type
            events = ledger.query_events(event_type="event1")
            assert len(events) == 2
            
            # Query by severity
            events = ledger.query_events(severity="CRITICAL")
            assert len(events) == 1


class TestAutoEnforcer:
    """Test auto-enforcer timeout monitoring."""
    
    def test_monitor_process(self):
        """Test process monitoring."""
        enforcer = AutoEnforcer(timeout_seconds=60, check_interval=1.0)
        
        pid = os.getpid()
        enforcer.monitor_process(pid, "test_command")
        
        assert pid in enforcer.monitored
        assert enforcer.monitored[pid].command == "test_command"
    
    def test_unmonitor_process(self):
        """Test process unmonitoring."""
        enforcer = AutoEnforcer(timeout_seconds=60)
        
        pid = os.getpid()
        enforcer.monitor_process(pid, "test")
        enforcer.unmonitor_process(pid)
        
        assert pid not in enforcer.monitored


class TestTripwireMonitor:
    """Test tripwire honeypot detection."""
    
    def test_deploy_tripwires(self):
        """Test tripwire deployment."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            tripwire = TripwireMonitor(workspace)
            
            tripwire.deploy()
            
            assert len(tripwire.deployed_paths) > 0
            
            # Check files exist
            for path in tripwire.deployed_paths:
                assert path.exists()
    
    def test_check_access(self):
        """Test tripwire access detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            tripwire = TripwireMonitor(workspace)
            
            tripwire.deploy()
            
            # Get first deployed tripwire
            tripwire_path = list(tripwire.deployed_paths)[0]
            
            # Check access
            triggered = tripwire.check_access(tripwire_path)
            
            assert triggered == True
            assert len(tripwire.access_log) == 1
    
    def test_cleanup(self):
        """Test tripwire cleanup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            tripwire = TripwireMonitor(workspace)
            
            tripwire.deploy()
            deployed_count = len(tripwire.deployed_paths)
            
            tripwire.cleanup()
            
            assert len(tripwire.deployed_paths) == 0


class TestLoopDetector:
    """Test loop detection."""
    
    def test_detect_loop(self):
        """Test high-velocity loop detection."""
        detector = LoopDetector(threshold=5, time_window=10.0)
        
        command = "npm install"
        
        # Execute command 5 times
        for _ in range(5):
            is_loop = detector.check_loop(command)
        
        # 5th execution should trigger loop detection
        assert is_loop == True
    
    def test_no_loop_different_commands(self):
        """Test that different commands don't trigger loop."""
        detector = LoopDetector(threshold=5, time_window=10.0)
        
        commands = ["cmd1", "cmd2", "cmd3", "cmd4", "cmd5"]
        
        for cmd in commands:
            is_loop = detector.check_loop(cmd)
            assert is_loop == False


class TestProcessMonitor:
    """Test process monitoring."""
    
    def test_register_parent(self):
        """Test parent process registration."""
        monitor = ProcessMonitor(max_children=10)
        
        parent_pid = 1234
        monitor.register_parent(parent_pid)
        
        assert parent_pid in monitor.process_tree
        assert monitor.process_tree[parent_pid] == []
    
    def test_check_and_register_child(self):
        """Test child process registration."""
        monitor = ProcessMonitor(max_children=3)
        
        parent_pid = 1234
        monitor.register_parent(parent_pid)
        
        # Register 3 children (should succeed)
        for i in range(3):
            monitor.check_and_register_child(parent_pid, 2000 + i)
        
        assert len(monitor.process_tree[parent_pid]) == 3
    
    def test_process_limit_exceeded(self):
        """Test process limit enforcement."""
        monitor = ProcessMonitor(max_children=2)
        
        parent_pid = 1234
        monitor.register_parent(parent_pid)
        
        # Register 2 children (should succeed)
        monitor.check_and_register_child(parent_pid, 2000)
        monitor.check_and_register_child(parent_pid, 2001)
        
        # 3rd child should raise exception
        with pytest.raises(ProcessLimitExceeded):
            monitor.check_and_register_child(parent_pid, 2002)


class TestKavachWrapper:
    """Test main Kavach wrapper."""
    
    def test_wrapper_initialization(self):
        """Test wrapper initialization."""
        policy = SecurityPolicy.default_standard()
        wrapper = KavachWrapper(policy=policy)
        
        assert wrapper.policy == policy
        assert wrapper.pii_sanitizer is not None
    
    def test_execute_success(self):
        """Test successful skill execution."""
        policy = SecurityPolicy.default_permissive()
        wrapper = KavachWrapper(policy=policy)
        
        def test_skill():
            return {"result": "success"}
        
        result = wrapper.execute(test_skill, "test_skill")
        
        assert result['status'] == 'success'
        assert result['result'] == {"result": "success"}
    
    def test_execute_with_pii_sanitization(self):
        """Test execution with PII sanitization."""
        policy = SecurityPolicy.default_standard()
        wrapper = KavachWrapper(policy=policy)
        
        def test_skill():
            return "My key: sk-1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
        
        result = wrapper.execute(test_skill, "test_skill")
        
        assert result['status'] == 'success'
        assert "sk-12345" in result['result']  # Prefix visible
        assert "*" in result['result']  # Should have redaction
        assert result['audit']['pii_detections'] > 0


class TestEnhancedAuditLedger:
    """Test enhanced audit ledger features."""
    
    def test_statistics(self):
        """Test audit statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = Path(tmpdir) / "audit.jsonl"
            ledger = EnhancedAuditLedger(ledger_path)
            
            # Log events
            ledger.log_event("event1", "skill1", "INFO", {})
            ledger.log_event("event2", "skill2", "CRITICAL", {})
            ledger.log_event("event1", "skill1", "HIGH", {})
            
            stats = ledger.get_statistics()
            
            assert stats.total_events == 3
            assert stats.critical_count == 1
            assert stats.high_count == 1
            assert "skill1" in stats.events_by_skill
            assert stats.events_by_skill["skill1"] == 2
    
    def test_notification_rate_limiting(self):
        """Test notification rate limiting."""
        config = NotificationConfig(
            enabled=True,
            severity_threshold="HIGH",
            channels=["log"],
            rate_limit=2,
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_path = Path(tmpdir) / "audit.jsonl"
            ledger = EnhancedAuditLedger(ledger_path, notification_config=config)
            
            # Log 5 CRITICAL events (should only notify for first 2)
            for i in range(5):
                ledger.log_event(f"event_{i}", "test_skill", "CRITICAL", {})
            
            # Check notification counter
            assert len(ledger.notification_counter["CRITICAL"]) == 2


class TestKavachWrapperSkill:
    """Test Kavach wrapper skill."""
    
    def test_action_status(self):
        """Test status action."""
        result = run({'action': 'status'})
        
        assert result['status'] == 'success'
        assert 'protected_skills' in result['result']
        assert 'unprotected_skills' in result['result']
    
    def test_action_enable(self):
        """Test enable action."""
        result = run({
            'action': 'enable',
            'skill_name': 'test_skill',
        })
        
        assert result['status'] == 'success'
        assert 'enabled' in result['message'].lower() or 'protected' in result['message'].lower()
    
    def test_action_audit_query(self):
        """Test audit query action."""
        result = run({
            'action': 'audit_query',
            'filters': {'limit': 10},
        })
        
        assert result['status'] == 'success'
        assert 'events' in result['result']
    
    def test_action_audit_verify(self):
        """Test audit verify action."""
        result = run({'action': 'audit_verify'})
        
        assert result['status'] in ['success', 'error']
        assert 'is_valid' in result['result']
    
    def test_missing_action(self):
        """Test missing action parameter."""
        result = run({})
        
        assert result['status'] == 'error'
        assert 'action' in result['message'].lower()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
