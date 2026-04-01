"""
Purple Engine - CTFd Manage Skill Implementation

Comprehensive lifecycle management for CTFd instances.
Handles challenges, teams, events, scoring, and configuration.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
import subprocess

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import CTFd API client
from api_client import CTFdAPIClient, CTFdChallenge

logger = logging.getLogger(__name__)


class CTFdManager:
    """
    CTFd lifecycle management and administration.
    
    Provides comprehensive management operations via CTFd API.
    """
    
    # Define destructive actions that require confirmation
    DESTRUCTIVE_ACTIONS = ['reset_event', 'delete_challenge', 'delete_team', 'restore_database']
    
    def __init__(self, ctfd_url: str, username: str = None, password: str = None, api_token: str = None):
        """Initialize CTFd manager."""
        self.client = CTFdAPIClient(ctfd_url, username, password, api_token)
        
        if not self.client.authenticated:
            raise ValueError("Failed to authenticate with CTFd")
        
        self.ctfd_url = ctfd_url
    
    # ==================== Challenge Management ====================
    
    def create_challenge(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new challenge."""
        try:
            # Build challenge object
            challenge = CTFdChallenge(
                name=params['name'],
                category=params['category'],
                description=params.get('description', ''),
                value=params.get('value', 100),
                state=params.get('state', 'visible'),
                type=params.get('type', 'standard'),
                flags=params.get('flags', []),
                tags=params.get('tags', []),
                hints=params.get('hints', []),
                requirements=params.get('requirements', [])
            )
            
            challenge_id = self.client.create_challenge(challenge)
            
            if not challenge_id:
                return {
                    'status': 'failed',
                    'message': 'Failed to create challenge'
                }
            
            # Upload files if provided
            files_uploaded = 0
            if 'files' in params:
                for file_path in params['files']:
                    if Path(file_path).exists():
                        if self.client.upload_file(challenge_id, file_path):
                            files_uploaded += 1
            
            return {
                'status': 'success',
                'action': 'create_challenge',
                'result': {
                    'challenge_id': challenge_id,
                    'name': params['name'],
                    'files_uploaded': files_uploaded
                },
                'message': f"Challenge '{params['name']}' created successfully",
                'affected_items': 1
            }
            
        except Exception as e:
            logger.error(f"Create challenge error: {e}", exc_info=True)
            return {
                'status': 'failed',
                'message': str(e)
            }
    
    def update_challenge(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Update existing challenge."""
        try:
            challenge_id = params['challenge_id']
            updates = params.get('updates', {})
            
            success = self.client.update_challenge(challenge_id, updates)
            
            return {
                'status': 'success' if success else 'failed',
                'action': 'update_challenge',
                'result': {
                    'challenge_id': challenge_id,
                    'updated_fields': list(updates.keys())
                },
                'message': f"Challenge {challenge_id} updated" if success else "Update failed",
                'affected_items': 1 if success else 0
            }
            
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}
    
    def delete_challenge(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Delete challenge (requires confirmation)."""
        if not params.get('confirm'):
            return {
                'status': 'error',
                'message': 'Delete challenge requires explicit confirmation (confirm=True)'
            }
        
        try:
            challenge_id = params['challenge_id']
            success = self.client.delete_challenge(challenge_id)
            
            return {
                'status': 'success' if success else 'failed',
                'action': 'delete_challenge',
                'result': {'challenge_id': challenge_id},
                'message': f"Challenge {challenge_id} deleted" if success else "Delete failed",
                'affected_items': 1 if success else 0
            }
            
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}
    
    def bulk_import(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Import multiple challenges from JSON."""
        try:
            input_file = params['input_file']
            
            if not Path(input_file).exists():
                return {'status': 'failed', 'message': f'File not found: {input_file}'}
            
            count = self.client.import_challenges(input_file)
            
            return {
                'status': 'success' if count > 0 else 'failed',
                'action': 'bulk_import',
                'result': {
                    'imported': count,
                    'source': input_file
                },
                'message': f"Imported {count} challenges from {input_file}",
                'affected_items': count
            }
            
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}
    
    def bulk_export(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Export challenges to JSON."""
        try:
            output_file = params.get('output_file', './challenges_export.json')
            
            success = self.client.export_challenges(output_file)
            
            if success:
                # Count exported challenges
                with open(output_file, 'r') as f:
                    data = json.load(f)
                    count = len(data.get('challenges', []))
                
                return {
                    'status': 'success',
                    'action': 'bulk_export',
                    'result': {
                        'exported': count,
                        'output_file': output_file
                    },
                    'message': f"Exported {count} challenges to {output_file}",
                    'affected_items': count
                }
            else:
                return {'status': 'failed', 'message': 'Export failed'}
                
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}
    
    def hide_challenge(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make challenge invisible."""
        return self.update_challenge({
            'challenge_id': params['challenge_id'],
            'updates': {'state': 'hidden'}
        })
    
    def show_challenge(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make challenge visible."""
        return self.update_challenge({
            'challenge_id': params['challenge_id'],
            'updates': {'state': 'visible'}
        })
    
    # ==================== Event Control ====================
    
    def start_event(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Start CTF event."""
        try:
            if 'start_time' in params:
                self.client.update_config('start', params['start_time'])
            
            # Enable features
            if params.get('enable_registration', True):
                self.client.update_config('registration_visibility', 'public')
            
            if params.get('enable_challenges', True):
                self.client.update_config('challenge_visibility', 'public')
            
            return {
                'status': 'success',
                'action': 'start_event',
                'message': 'Event started successfully',
                'result': {
                    'start_time': params.get('start_time', 'immediate'),
                    'registration_enabled': params.get('enable_registration', True),
                    'challenges_enabled': params.get('enable_challenges', True)
                }
            }
            
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}
    
    def pause_event(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Pause event (freeze submissions)."""
        try:
            # Implement pause by setting future end time or config flag
            # CTFd doesn't have native pause, so we freeze scoreboard
            if params.get('freeze_submissions'):
                self.client.update_config('freeze', datetime.now().isoformat())
            
            if params.get('hide_scoreboard'):
                self.client.update_config('score_visibility', 'hidden')
            
            return {
                'status': 'success',
                'action': 'pause_event',
                'message': 'Event paused',
                'result': params
            }
            
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}
    
    def end_event(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """End CTF event."""
        try:
            if 'end_time' in params:
                self.client.update_config('end', params['end_time'])
            else:
                self.client.update_config('end', datetime.now().isoformat())
            
            if params.get('freeze_scoreboard', True):
                self.client.update_config('freeze', datetime.now().isoformat())
            
            if params.get('close_registration', True):
                self.client.update_config('registration_visibility', 'private')
            
            return {
                'status': 'success',
                'action': 'end_event',
                'message': 'Event ended successfully',
                'result': {
                    'end_time': params.get('end_time', 'now'),
                    'scoreboard_frozen': params.get('freeze_scoreboard', True)
                }
            }
            
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}
    
    def reset_event(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Reset event (DESTRUCTIVE - requires confirmation)."""
        if not params.get('confirm'):
            return {
                'status': 'error',
                'message': 'Reset event requires explicit confirmation (confirm=True) - THIS WILL DELETE ALL SUBMISSIONS!'
            }
        
        try:
            # Create backup first
            backup_path = self._create_backup()
            
            # Reset would require direct database access or CTFd admin panel
            # For now, return instruction
            return {
                'status': 'partial',
                'action': 'reset_event',
                'message': 'Event reset requires manual database operation or CTFd admin panel',
                'result': {
                    'backup_created': backup_path,
                    'instruction': 'Use CTFd admin panel to reset or execute: DELETE FROM submissions; DELETE FROM solves;'
                },
                'warnings': ['Backup created before reset attempt']
            }
            
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}
    
    # ==================== Scoring Operations ====================
    
    def get_scoreboard(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get current scoreboard."""
        try:
            top_n = params.get('top_n', 10)
            scoreboard = self.client.get_scoreboard(count=top_n)
            
            return {
                'status': 'success',
                'action': 'get_scoreboard',
                'result': {
                    'teams': scoreboard,
                    'count': len(scoreboard)
                },
                'message': f'Retrieved top {len(scoreboard)} teams'
            }
            
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}
    
    def get_statistics(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get comprehensive event statistics."""
        try:
            challenges = self.client.list_challenges(visible_only=False)
            
            stats = {
                'total_challenges': len(challenges),
                'challenges_by_category': {}
            }
            
            # Category breakdown
            for challenge in challenges:
                cat = challenge.category
                if cat not in stats['challenges_by_category']:
                    stats['challenges_by_category'][cat] = {
                        'count': 0,
                        'total_points': 0
                    }
                stats['challenges_by_category'][cat]['count'] += 1
                stats['challenges_by_category'][cat]['total_points'] += challenge.value
            
            return {
                'status': 'success',
                'action': 'get_statistics',
                'result': stats,
                'message': 'Statistics retrieved successfully'
            }
            
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}
    
    # ==================== Configuration ====================
    
    def backup_database(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Create database backup."""
        try:
            backup_path = self._create_backup(include_uploads=params.get('include_uploads', True))
            
            return {
                'status': 'success',
                'action': 'backup_database',
                'result': {
                    'backup_path': backup_path
                },
                'message': f'Backup created: {backup_path}'
            }
            
        except Exception as e:
            return {'status': 'failed', 'message': str(e)}
    
    def _create_backup(self, include_uploads: bool = True) -> Optional[str]:
        """Internal backup creation helper."""
        try:
            backup_dir = Path('./backups')
            backup_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = backup_dir / f"ctfd_backup_{timestamp}.sql"
            
            # Backup database via Docker
            cmd = f"docker exec purple_ctfd_db mysqldump -u ctfd -pctfd ctfd > {backup_file}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0 and backup_file.exists():
                logger.info(f"Backup created: {backup_file}")
                return str(backup_file)
            else:
                logger.error(f"Backup failed: {result.stderr}")
                return None
                
        except Exception as e:
            logger.error(f"Backup error: {e}")
            return None
    
    # ==================== Main Execution ====================
    
    def execute_action(self, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute management action."""
        
        # Safety check for destructive actions
        if action in self.DESTRUCTIVE_ACTIONS and not params.get('confirm'):
            return {
                'status': 'error',
                'message': f"Action '{action}' is destructive and requires explicit confirmation (confirm=True)"
            }
        
        # Route to appropriate handler
        action_map = {
            # Challenge management
            'create_challenge': self.create_challenge,
            'update_challenge': self.update_challenge,
            'delete_challenge': self.delete_challenge,
            'bulk_import': self.bulk_import,
            'bulk_export': self.bulk_export,
            'hide_challenge': self.hide_challenge,
            'show_challenge': self.show_challenge,
            
            # Event control
            'start_event': self.start_event,
            'pause_event': self.pause_event,
            'end_event': self.end_event,
            'reset_event': self.reset_event,
            
            # Scoring & stats
            'get_scoreboard': self.get_scoreboard,
            'get_statistics': self.get_statistics,
            
            # Configuration
            'backup_database': self.backup_database,
        }
        
        handler = action_map.get(action)
        
        if not handler:
            return {
                'status': 'error',
                'message': f"Unknown action: {action}",
                'available_actions': list(action_map.keys())
            }
        
        try:
            return handler(params)
        except Exception as e:
            logger.error(f"Action '{action}' error: {e}", exc_info=True)
            return {
                'status': 'failed',
                'action': action,
                'message': str(e)
            }


def run(inputs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for ctfd_manage skill.
    
    Args:
        inputs: Dictionary with management parameters
        
    Returns:
        Dictionary with action results
    """
    # Extract parameters
    ctfd_url = inputs.get('ctfd_url')
    username = inputs.get('username')
    password = inputs.get('password')
    api_token = inputs.get('api_token')
    action = inputs.get('action')
    params = inputs.get('params', {})
    
    # Validate inputs
    if not ctfd_url:
        return {'status': 'error', 'message': 'ctfd_url is required'}
    
    if not (api_token or (username and password)):
        return {'status': 'error', 'message': 'Must provide api_token or username+password'}
    
    if not action:
        return {'status': 'error', 'message': 'action is required'}
    
    try:
        # Initialize manager
        manager = CTFdManager(
            ctfd_url=ctfd_url,
            username=username,
            password=password,
            api_token=api_token
        )
        
        # Execute action
        result = manager.execute_action(action, params)
        
        return result
        
    except Exception as e:
        logger.error(f"CTFd manage skill error: {e}", exc_info=True)
        return {
            'status': 'error',
            'message': str(e)
        }


if __name__ == '__main__':
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    test_inputs = {
        'ctfd_url': 'http://localhost:8000',
        'username': 'admin',
        'password': 'admin',
        'action': 'get_statistics',
        'params': {}
    }
    
    result = run(test_inputs)
    print(json.dumps(result, indent=2))
