"""
CTFd API Client for Purple Engine

Based on original JohnHammond/katana ctfd.py logic (commit 04379957).
Provides comprehensive CTFd REST API interface for challenge management,
flag submission, and event orchestration.

Architecture:
- RESTful API client with session management
- Auto-authentication with admin/user credentials
- Challenge lifecycle operations (list, get, create, update, delete)
- Flag submission and validation
- Team and scoring management
- Export/import configurations
"""

import requests
import json
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class CTFdChallenge:
    """CTFd challenge data model"""
    id: Optional[int] = None
    name: str = ""
    category: str = ""
    description: str = ""
    value: int = 100
    state: str = "visible"  # visible, hidden
    type: str = "standard"  # standard, dynamic
    files: List[str] = None
    flags: List[Dict[str, str]] = None
    tags: List[str] = None
    hints: List[Dict[str, Any]] = None
    requirements: List[int] = None  # Challenge IDs that must be solved first
    
    def __post_init__(self):
        if self.files is None:
            self.files = []
        if self.flags is None:
            self.flags = []
        if self.tags is None:
            self.tags = []
        if self.hints is None:
            self.hints = []
        if self.requirements is None:
            self.requirements = []
    
    def to_dict(self):
        """Convert to CTFd API format"""
        return {k: v for k, v in asdict(self).items() if v is not None and k != 'id'}


@dataclass
class CTFdSubmission:
    """Flag submission result"""
    correct: bool
    message: str
    challenge_id: int
    timestamp: datetime


class CTFdAPIClient:
    """
    CTFd API Client with full lifecycle management.
    
    Supports:
    - Authentication (admin/user)
    - Challenge CRUD operations
    - Flag submission and validation
    - Team management
    - Event configuration
    - Challenge pack import/export
    
    Based on CTFd v3.x API specification.
    """
    
    def __init__(self, base_url: str, username: str = None, password: str = None, api_token: str = None):
        """
        Initialize CTFd API client.
        
        Args:
            base_url: CTFd instance URL (e.g., http://localhost:8000)
            username: Admin/user username (for password auth)
            password: Admin/user password (for password auth)
            api_token: API token (alternative to username/password)
        """
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.authenticated = False
        self.user_info = None
        
        # Set up session headers
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        # Authenticate
        if api_token:
            self.session.headers['Authorization'] = f'Token {api_token}'
            self.authenticated = True
        elif username and password:
            self.login(username, password)
    
    def login(self, username: str, password: str) -> bool:
        """
        Authenticate with CTFd using username/password.
        
        Args:
            username: CTFd username
            password: CTFd password
            
        Returns:
            True if authentication successful
        """
        try:
            # Get nonce for CSRF protection
            response = self.session.get(f'{self.base_url}/login')
            response.raise_for_status()
            
            # Extract nonce from login page
            nonce = self._extract_nonce(response.text)
            
            # Perform login
            login_data = {
                'name': username,
                'password': password,
                'nonce': nonce
            }
            
            response = self.session.post(
                f'{self.base_url}/login',
                data=login_data,
                allow_redirects=False
            )
            
            if response.status_code == 302 or 'session' in self.session.cookies:
                self.authenticated = True
                self.user_info = self._get_user_info()
                logger.info(f"Authenticated as {username}")
                return True
            else:
                logger.error(f"Login failed for {username}")
                return False
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False
    
    def _extract_nonce(self, html: str) -> str:
        """Extract CSRF nonce from HTML page"""
        # Simple extraction - in production use BeautifulSoup
        import re
        match = re.search(r'name="nonce"\s+value="([^"]+)"', html)
        if match:
            return match.group(1)
        return ""
    
    def _get_user_info(self) -> Optional[Dict]:
        """Get current user information"""
        try:
            response = self.session.get(f'{self.base_url}/api/v1/users/me')
            response.raise_for_status()
            return response.json()['data']
        except Exception as e:
            logger.warning(f"Could not get user info: {e}")
            return None
    
    # ==================== Challenge Operations ====================
    
    def list_challenges(self, category: str = None, visible_only: bool = True) -> List[CTFdChallenge]:
        """
        List all challenges.
        
        Args:
            category: Filter by category (optional)
            visible_only: Only return visible challenges (default: True)
            
        Returns:
            List of CTFdChallenge objects
        """
        try:
            response = self.session.get(f'{self.base_url}/api/v1/challenges')
            response.raise_for_status()
            data = response.json()
            
            challenges = []
            for item in data.get('data', []):
                # Get full challenge details
                challenge = self.get_challenge(item['id'])
                if challenge:
                    # Apply filters
                    if category and challenge.category != category:
                        continue
                    if visible_only and challenge.state != 'visible':
                        continue
                    challenges.append(challenge)
            
            return challenges
            
        except Exception as e:
            logger.error(f"Error listing challenges: {e}")
            return []
    
    def get_challenge(self, challenge_id: int) -> Optional[CTFdChallenge]:
        """
        Get detailed information about a specific challenge.
        
        Args:
            challenge_id: Challenge ID
            
        Returns:
            CTFdChallenge object or None
        """
        try:
            response = self.session.get(f'{self.base_url}/api/v1/challenges/{challenge_id}')
            response.raise_for_status()
            data = response.json()['data']
            
            return CTFdChallenge(
                id=data['id'],
                name=data['name'],
                category=data.get('category', ''),
                description=data.get('description', ''),
                value=data.get('value', 100),
                state=data.get('state', 'visible'),
                type=data.get('type', 'standard'),
                files=[f['location'] for f in data.get('files', [])],
                tags=[t['value'] for t in data.get('tags', [])],
                hints=data.get('hints', []),
                requirements=data.get('requirements', {}).get('prerequisites', [])
            )
            
        except Exception as e:
            logger.error(f"Error getting challenge {challenge_id}: {e}")
            return None
    
    def create_challenge(self, challenge: CTFdChallenge) -> Optional[int]:
        """
        Create a new challenge.
        
        Args:
            challenge: CTFdChallenge object with challenge details
            
        Returns:
            Challenge ID if successful, None otherwise
        """
        try:
            response = self.session.post(
                f'{self.base_url}/api/v1/challenges',
                json=challenge.to_dict()
            )
            response.raise_for_status()
            challenge_id = response.json()['data']['id']
            logger.info(f"Created challenge '{challenge.name}' with ID {challenge_id}")
            
            # Add flags if provided
            if challenge.flags:
                for flag in challenge.flags:
                    self.add_flag(challenge_id, flag.get('content', ''), flag.get('type', 'static'))
            
            return challenge_id
            
        except Exception as e:
            logger.error(f"Error creating challenge: {e}")
            return None
    
    def update_challenge(self, challenge_id: int, updates: Dict[str, Any]) -> bool:
        """
        Update an existing challenge.
        
        Args:
            challenge_id: Challenge ID
            updates: Dictionary of fields to update
            
        Returns:
            True if successful
        """
        try:
            response = self.session.patch(
                f'{self.base_url}/api/v1/challenges/{challenge_id}',
                json=updates
            )
            response.raise_for_status()
            logger.info(f"Updated challenge {challenge_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating challenge {challenge_id}: {e}")
            return False
    
    def delete_challenge(self, challenge_id: int) -> bool:
        """
        Delete a challenge.
        
        Args:
            challenge_id: Challenge ID
            
        Returns:
            True if successful
        """
        try:
            response = self.session.delete(f'{self.base_url}/api/v1/challenges/{challenge_id}')
            response.raise_for_status()
            logger.info(f"Deleted challenge {challenge_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting challenge {challenge_id}: {e}")
            return False
    
    # ==================== Flag Operations ====================
    
    def add_flag(self, challenge_id: int, flag_content: str, flag_type: str = 'static') -> bool:
        """
        Add a flag to a challenge.
        
        Args:
            challenge_id: Challenge ID
            flag_content: Flag string (e.g., "flag{example}")
            flag_type: Flag type ('static' or 'regex')
            
        Returns:
            True if successful
        """
        try:
            flag_data = {
                'challenge_id': challenge_id,
                'content': flag_content,
                'type': flag_type,
                'data': ''  # Additional data for regex flags
            }
            
            response = self.session.post(
                f'{self.base_url}/api/v1/flags',
                json=flag_data
            )
            response.raise_for_status()
            logger.info(f"Added flag to challenge {challenge_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding flag: {e}")
            return False
    
    def submit_flag(self, challenge_id: int, flag: str) -> CTFdSubmission:
        """
        Submit a flag for a challenge.
        
        Args:
            challenge_id: Challenge ID
            flag: Flag string to submit
            
        Returns:
            CTFdSubmission object with result
        """
        try:
            submission_data = {
                'challenge_id': challenge_id,
                'submission': flag
            }
            
            response = self.session.post(
                f'{self.base_url}/api/v1/challenges/attempt',
                json=submission_data
            )
            response.raise_for_status()
            data = response.json()['data']
            
            result = CTFdSubmission(
                correct=(data['status'] == 'correct'),
                message=data.get('message', ''),
                challenge_id=challenge_id,
                timestamp=datetime.now()
            )
            
            if result.correct:
                logger.info(f"CORRECT flag submitted for challenge {challenge_id}")
            else:
                logger.warning(f"INCORRECT flag for challenge {challenge_id}: {result.message}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error submitting flag: {e}")
            return CTFdSubmission(
                correct=False,
                message=f"Submission error: {str(e)}",
                challenge_id=challenge_id,
                timestamp=datetime.now()
            )
    
    # ==================== File Operations ====================
    
    def upload_file(self, challenge_id: int, file_path: str) -> bool:
        """
        Upload a file to a challenge.
        
        Args:
            challenge_id: Challenge ID
            file_path: Path to file to upload
            
        Returns:
            True if successful
        """
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                response = self.session.post(
                    f'{self.base_url}/api/v1/files',
                    files=files,
                    data={'challenge_id': challenge_id, 'type': 'challenge'}
                )
            response.raise_for_status()
            logger.info(f"Uploaded file to challenge {challenge_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error uploading file: {e}")
            return False
    
    def download_file(self, file_url: str, save_path: str) -> bool:
        """
        Download a challenge file.
        
        Args:
            file_url: Relative or absolute URL to file
            save_path: Local path to save file
            
        Returns:
            True if successful
        """
        try:
            if not file_url.startswith('http'):
                file_url = f'{self.base_url}{file_url}'
            
            response = self.session.get(file_url, stream=True)
            response.raise_for_status()
            
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            logger.info(f"Downloaded file to {save_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error downloading file: {e}")
            return False
    
    # ==================== Team/Scoreboard Operations ====================
    
    def get_scoreboard(self, count: int = 10) -> List[Dict]:
        """Get top teams from scoreboard"""
        try:
            response = self.session.get(f'{self.base_url}/api/v1/scoreboard/top/{count}')
            response.raise_for_status()
            return response.json()['data']
        except Exception as e:
            logger.error(f"Error getting scoreboard: {e}")
            return []
    
    def get_solves(self, challenge_id: int) -> List[Dict]:
        """Get all solves for a challenge"""
        try:
            response = self.session.get(f'{self.base_url}/api/v1/challenges/{challenge_id}/solves')
            response.raise_for_status()
            return response.json()['data']
        except Exception as e:
            logger.error(f"Error getting solves: {e}")
            return []
    
    # ==================== Configuration Operations ====================
    
    def get_config(self) -> Dict:
        """Get CTFd configuration"""
        try:
            response = self.session.get(f'{self.base_url}/api/v1/configs')
            response.raise_for_status()
            return response.json()['data']
        except Exception as e:
            logger.error(f"Error getting config: {e}")
            return {}
    
    def update_config(self, key: str, value: Any) -> bool:
        """Update a configuration value"""
        try:
            response = self.session.patch(
                f'{self.base_url}/api/v1/configs',
                json={key: value}
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Error updating config: {e}")
            return False
    
    # ==================== Utility Methods ====================
    
    def health_check(self) -> bool:
        """Check if CTFd instance is accessible"""
        try:
            response = self.session.get(f'{self.base_url}/api/v1/healthcheck', timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def export_challenges(self, output_file: str) -> bool:
        """Export all challenges to JSON file"""
        try:
            challenges = self.list_challenges(visible_only=False)
            data = {
                'challenges': [asdict(c) for c in challenges],
                'exported_at': datetime.now().isoformat()
            }
            
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Exported {len(challenges)} challenges to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting challenges: {e}")
            return False
    
    def import_challenges(self, input_file: str) -> int:
        """Import challenges from JSON file"""
        try:
            with open(input_file, 'r') as f:
                data = json.load(f)
            
            count = 0
            for challenge_data in data.get('challenges', []):
                challenge = CTFdChallenge(**challenge_data)
                if self.create_challenge(challenge):
                    count += 1
            
            logger.info(f"Imported {count} challenges from {input_file}")
            return count
            
        except Exception as e:
            logger.error(f"Error importing challenges: {e}")
            return 0
