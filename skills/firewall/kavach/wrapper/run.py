"""
Kavach Wrapper Skill - Run Implementation

Provides CLI and MCP interface for managing Kavach AI Firewall operations.

Usage:
    # Via MCP
    result = run({
        'action': 'audit_query',
        'filters': {'severity': 'CRITICAL', 'limit': 50}
    })
    
    # Via CLI (through purple-engine)
    purple-engine kavach status
    purple-engine kavach enable research_agent
    purple-engine kavach audit-query --severity CRITICAL
"""

import sys
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging

# Add project root to path
project_root = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(project_root))

from skills.firewall.kavach import (
    KavachWrapper,
    SecurityPolicy,
    PhantomWorkspace,
    AuditLedger,
    PIISanitizer,
    TripwireMonitor,
)
from skills.firewall.kavach.exceptions import KavachSecurityViolation

logger = logging.getLogger(__name__)


class KavachWrapperSkill:
    """
    Kavach Wrapper Skill Implementation.
    
    Manages Kavach security layer operations for Purple Engine.
    """
    
    # Global state tracking (in-memory for now, can be persisted later)
    protected_skills: Dict[str, bool] = {}
    active_wrappers: Dict[str, KavachWrapper] = {}
    
    def __init__(
        self,
        workspace: Optional[Path] = None,
        policy_path: Optional[Path] = None,
        audit_ledger_path: Optional[Path] = None,
    ):
        self.workspace = Path(workspace) if workspace else Path.cwd()
        
        # Load security policy
        if policy_path is None:
            policy_path = project_root / "configs" / "kavach" / "security-policies.yaml"
        
        if policy_path.exists():
            self.policy = SecurityPolicy.from_yaml(policy_path)
        else:
            logger.warning(f"Policy file not found: {policy_path}, using default standard")
            self.policy = SecurityPolicy.default_standard()
        
        # Initialize audit ledger
        if audit_ledger_path is None:
            audit_ledger_path = Path.home() / ".purple-engine" / "kavach_audit.jsonl"
        
        self.audit_ledger = AuditLedger(audit_ledger_path)
        
        # Initialize components
        self.pii_sanitizer = PIISanitizer(custom_patterns=self.policy.pii_patterns)
        
        if self.policy.enable_phantom_workspace:
            self.phantom_workspace = PhantomWorkspace(
                self.workspace,
                phantom_dir_name=self.policy.phantom_dir_name
            )
        else:
            self.phantom_workspace = None
        
        if self.policy.enable_tripwires:
            self.tripwire_monitor = TripwireMonitor(
                self.workspace,
                custom_tripwires={k: v for k, v in zip(
                    self.policy.tripwire_files,
                    ["{}" for _ in self.policy.tripwire_files]
                )} if isinstance(self.policy.tripwire_files, list) else {}
            )
        else:
            self.tripwire_monitor = None
    
    def execute_action(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute Kavach wrapper action.
        
        Args:
            action: Action to perform
            params: Action parameters
        
        Returns:
            Result dictionary with status, message, and result data
        """
        action_handlers = {
            'status': self.action_status,
            'enable': self.action_enable,
            'disable': self.action_disable,
            'audit_query': self.action_audit_query,
            'audit_verify': self.action_audit_verify,
            'phantom_commit': self.action_phantom_commit,
            'phantom_rollback': self.action_phantom_rollback,
            'phantom_status': self.action_phantom_status,
            'tripwire_deploy': self.action_tripwire_deploy,
            'tripwire_cleanup': self.action_tripwire_cleanup,
            'tripwire_status': self.action_tripwire_status,
            'pii_summary': self.action_pii_summary,
        }
        
        handler = action_handlers.get(action)
        if not handler:
            return {
                'status': False,
                'summary': f"Unknown action: {action}",
                'available_actions': list(action_handlers.keys()),
            }
        
        try:
            result = handler(params)
            return result
        except Exception as e:
            logger.error(f"Action {action} failed: {e}", exc_info=True)
            return {
                'status': False,
                'summary': str(e),
                'result': {'error_type': type(e).__name__}
            }
    
    def action_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Show protection status for all skills."""
        protected = [name for name, enabled in self.protected_skills.items() if enabled]
        unprotected = [name for name, enabled in self.protected_skills.items() if not enabled]
        
        # Get recent security events
        recent_events = self.audit_ledger.query_events(limit=10)
        
        return {
            'status': True,
            'summary': f"{len(protected)} skills protected, {len(unprotected)} unprotected",
            'result': {
                'protected_skills': protected,
                'unprotected_skills': unprotected,
                'total_skills': len(self.protected_skills),
                'recent_events': recent_events,
                'policy_profile': getattr(self.policy, 'default_profile', 'standard'),
            }
        }
    
    def action_enable(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Enable Kavach protection for a skill."""
        skill_name = params.get('skill_name')
        if not skill_name:
            return {
                'status': False,
                'summary': 'skill_name parameter required',
            }
        
        # Mark skill as protected
        self.protected_skills[skill_name] = True
        
        # Log event
        self.audit_ledger.log_event(
            event_type="protection_enabled",
            skill_name=skill_name,
            severity="INFO",
            details={},
        )
        
        return {
            'status': True,
            'summary': f"Kavach protection enabled for {skill_name}",
            'result': {
                'skill_name': skill_name,
                'protected': True,
            }
        }
    
    def action_disable(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Disable Kavach protection for a skill."""
        skill_name = params.get('skill_name')
        if not skill_name:
            return {
                'status': False,
                'summary': 'skill_name parameter required',
            }
        
        # Mark skill as unprotected
        self.protected_skills[skill_name] = False
        
        # Log event
        self.audit_ledger.log_event(
            event_type="protection_disabled",
            skill_name=skill_name,
            severity="MEDIUM",
            details={'reason': 'manual_disable'},
        )
        
        return {
            'status': True,
            'summary': f"Kavach protection disabled for {skill_name}",
            'result': {
                'skill_name': skill_name,
                'protected': False,
            }
        }
    
    def action_audit_query(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query audit log with filters."""
        filters = params.get('filters', {})
        
        event_type = filters.get('event_type')
        severity = filters.get('severity')
        skill_name = filters.get('skill_name')
        limit = filters.get('limit', 100)
        
        events = self.audit_ledger.query_events(
            event_type=event_type,
            skill_name=skill_name,
            severity=severity,
            limit=limit,
        )
        
        # Aggregate statistics
        event_types_count = {}
        severity_count = {}
        for event in events:
            event_type_val = event.get('event_type', 'unknown')
            severity_val = event.get('severity', 'UNKNOWN')
            
            event_types_count[event_type_val] = event_types_count.get(event_type_val, 0) + 1
            severity_count[severity_val] = severity_count.get(severity_val, 0) + 1
        
        return {
            'status': True,
            'summary': f"Found {len(events)} matching events",
            'result': {
                'events': events,
                'count': len(events),
                'statistics': {
                    'event_types': event_types_count,
                    'severities': severity_count,
                },
                'filters_applied': filters,
            }
        }
    
    def action_audit_verify(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Verify audit ledger integrity."""
        is_valid, errors = self.audit_ledger.verify_integrity()
        
        severity = "INFO" if is_valid else "CRITICAL"
        
        # Log verification result
        self.audit_ledger.log_event(
            event_type="integrity_check",
            skill_name="kavach_wrapper",
            severity=severity,
            details={'is_valid': is_valid, 'error_count': len(errors)},
        )
        
        return {
            'status': True if is_valid else False,
            'summary': 'Audit ledger is valid' if is_valid else f'Audit ledger corrupted: {len(errors)} errors',
            'result': {
                'is_valid': is_valid,
                'errors': errors,
                'ledger_path': str(self.audit_ledger.ledger_path),
            }
        }
    
    def action_phantom_commit(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Commit phantom workspace changes to real workspace."""
        if not self.phantom_workspace:
            return {
                'status': False,
                'summary': 'Phantom workspace not enabled in security policy',
            }
        
        # Get operation summary before committing
        operations = self.phantom_workspace.get_operation_summary()
        
        # Commit changes
        self.phantom_workspace.commit_changes()
        
        # Log event
        self.audit_ledger.log_event(
            event_type="phantom_commit",
            skill_name="kavach_wrapper",
            severity="HIGH",
            details={'operations': operations},
        )
        
        return {
            'status': True,
            'summary': f"Committed {sum(operations.values())} phantom operations",
            'result': {
                'operations': operations,
                'committed': True,
            }
        }
    
    def action_phantom_rollback(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback specific file from snapshot."""
        if not self.phantom_workspace:
            return {
                'status': False,
                'summary': 'Phantom workspace not enabled in security policy',
            }
        
        file_path = params.get('file_path')
        if not file_path:
            return {
                'status': False,
                'summary': 'file_path parameter required',
            }
        
        file_path = Path(file_path)
        
        # Attempt rollback
        success = self.phantom_workspace.rollback_file(file_path)
        
        if success:
            # Log event
            self.audit_ledger.log_event(
                event_type="file_rollback",
                skill_name="kavach_wrapper",
                severity="MEDIUM",
                details={'file_path': str(file_path)},
            )
            
            return {
                'status': True,
                'summary': f"Rolled back file: {file_path}",
                'result': {
                    'file_path': str(file_path),
                    'rolled_back': True,
                }
            }
        else:
            return {
                'status': False,
                'summary': f"No snapshot available for: {file_path}",
                'result': {
                    'file_path': str(file_path),
                    'rolled_back': False,
                }
            }
    
    def action_phantom_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Show phantom workspace operations."""
        if not self.phantom_workspace:
            return {
                'status': False,
                'summary': 'Phantom workspace not enabled in security policy',
            }
        
        operations = self.phantom_workspace.get_operation_summary()
        
        # Get snapshot info
        snapshot_count = len(self.phantom_workspace.file_snapshots)
        snapshot_files = [str(p) for p in self.phantom_workspace.file_snapshots.keys()]
        
        return {
            'status': True,
            'summary': f"{sum(operations.values())} phantom operations, {snapshot_count} snapshots",
            'result': {
                'operations': operations,
                'snapshots': {
                    'count': snapshot_count,
                    'files': snapshot_files,
                },
                'phantom_root': str(self.phantom_workspace.phantom_root),
            }
        }
    
    def action_tripwire_deploy(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Deploy honeypot tripwire files."""
        if not self.tripwire_monitor:
            return {
                'status': False,
                'summary': 'Tripwires not enabled in security policy',
            }
        
        self.tripwire_monitor.deploy()
        
        deployed_count = len(self.tripwire_monitor.deployed_paths)
        
        # Log event
        self.audit_ledger.log_event(
            event_type="tripwires_deployed",
            skill_name="kavach_wrapper",
            severity="INFO",
            details={'count': deployed_count},
        )
        
        return {
            'status': True,
            'summary': f"Deployed {deployed_count} tripwire files",
            'result': {
                'deployed_count': deployed_count,
                'tripwire_files': [str(p) for p in self.tripwire_monitor.deployed_paths],
            }
        }
    
    def action_tripwire_cleanup(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Remove all deployed tripwire files."""
        if not self.tripwire_monitor:
            return {
                'status': False,
                'summary': 'Tripwires not enabled in security policy',
            }
        
        removed_count = len(self.tripwire_monitor.deployed_paths)
        
        self.tripwire_monitor.cleanup()
        
        # Log event
        self.audit_ledger.log_event(
            event_type="tripwires_cleaned",
            skill_name="kavach_wrapper",
            severity="INFO",
            details={'count': removed_count},
        )
        
        return {
            'status': True,
            'summary': f"Removed {removed_count} tripwire files",
            'result': {
                'removed_count': removed_count,
            }
        }
    
    def action_tripwire_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Show tripwire access log."""
        if not self.tripwire_monitor:
            return {
                'status': False,
                'summary': 'Tripwires not enabled in security policy',
            }
        
        access_log = self.tripwire_monitor.get_access_log()
        triggered_count = sum(1 for event in access_log if event.get('triggered'))
        
        return {
            'status': True,
            'summary': f"{triggered_count} tripwire triggers detected",
            'result': {
                'access_log': access_log,
                'triggered_count': triggered_count,
                'total_events': len(access_log),
            }
        }
    
    def action_pii_summary(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get PII detection summary."""
        summary = self.pii_sanitizer.get_detection_summary()
        total_detections = sum(summary.values())
        
        return {
            'status': True,
            'summary': f"{total_detections} PII instances detected",
            'result': {
                'summary': summary,
                'total_detections': total_detections,
                'pii_types': list(summary.keys()),
            }
        }


def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for Kavach Wrapper Skill.
    
    Args:
        params: {
            'action': str,          # Required: Action to perform
            'skill_name': str,      # Optional: Skill name (for enable/disable)
            'file_path': str,       # Optional: File path (for phantom_rollback)
            'filters': dict,        # Optional: Filters for audit_query
        }
    
    Returns:
        {
            'status': bool,
            'summary': str,
            'result': dict,
        }
    """
    # Validate action parameter
    action = params.get('action')
    if not action:
        return {
            'status': False,
            'summary': 'action parameter required',
            'available_actions': [
                'status', 'enable', 'disable',
                'audit_query', 'audit_verify',
                'phantom_commit', 'phantom_rollback', 'phantom_status',
                'tripwire_deploy', 'tripwire_cleanup', 'tripwire_status',
                'pii_summary',
            ],
        }
    
    # Initialize skill
    try:
        skill = KavachWrapperSkill(
            workspace=params.get('workspace'),
            policy_path=params.get('policy_path'),
            audit_ledger_path=params.get('audit_ledger_path'),
        )
    except Exception as e:
        return {
            'status': False,
            'summary': f"Failed to initialize Kavach wrapper: {e}",
            'result': {'error_type': type(e).__name__}
        }
    
    # Execute action
    return skill.execute_action(action, params)


def main():
    """CLI entry point for testing."""
    if len(sys.argv) < 2:
        print("Usage: python run.py <action> [params...]")
        print("Example: python run.py status")
        print("Example: python run.py enable research_agent")
        print("Example: python run.py audit_query --severity CRITICAL")
        sys.exit(1)
    
    action = sys.argv[1]
    
    # Parse remaining args as params
    params = {'action': action}
    
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg.startswith('--'):
            key = arg[2:]
            if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith('--'):
                value = sys.argv[i + 1]
                i += 2
            else:
                value = True
                i += 1
            
            # Handle filters specially
            if key in ['severity', 'event_type', 'skill_name', 'limit']:
                if 'filters' not in params:
                    params['filters'] = {}
                params['filters'][key] = value
            else:
                params[key] = value
        else:
            # Positional arg (e.g., skill name)
            if 'skill_name' not in params:
                params['skill_name'] = arg
            i += 1
    
    # Execute
    result = run(params)
    
    # Pretty print result
    print(json.dumps(result, indent=2))
    
    # Exit with appropriate code
    sys.exit(0 if result.get('status') is True else 1)


if __name__ == '__main__':
    main()
