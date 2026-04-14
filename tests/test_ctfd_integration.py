"""
Purple Engine - CTFd Integration Tests

Comprehensive test suite for CTFd API client, setup, solve, and manage skills.
Extends existing Katana test suite (66 tests) with full CTFd coverage.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from skills.api_client import CTFdAPIClient, CTFdChallenge, CTFdSubmission


class TestCTFdAPIClient:
    """Test CTFd API client functionality."""
    
    @pytest.fixture
    def mock_session(self):
        """Create mock requests session."""
        with patch('server.utils.ctfd_client.requests.Session') as mock:
            session = mock.return_value
            session.cookies = {'session': 'fake-session-id'}
            yield session
    
    def test_client_initialization_with_token(self, mock_session):
        """Test API client initialization with token."""
        client = CTFdAPIClient(
            base_url='http://localhost:8000',
            api_token='test-token'
        )
        
        assert client.base_url == 'http://localhost:8000'
        assert client.authenticated == True
        # When using token, the header is set during init
        mock_session.headers.__setitem__.assert_called_with('Authorization', 'Token test-token')
    
    def test_client_initialization_with_password(self, mock_session):
        """Test API client initialization with username/password."""
        mock_session.get.return_value.text = '<input name="nonce" value="test-nonce">'
        mock_session.post.return_value.status_code = 302
        
        client = CTFdAPIClient(
            base_url='http://localhost:8000',
            username='admin',
            password='admin'
        )
        
        assert client.authenticated == True
        mock_session.post.assert_called_once()
    
    def test_list_challenges(self, mock_session):
        """Test listing challenges."""
        # Mock API responses
        mock_session.get.return_value.json.return_value = {
            'data': [
                {'id': 1, 'name': 'Challenge 1', 'category': 'crypto'},
                {'id': 2, 'name': 'Challenge 2', 'category': 'web'}
            ]
        }
        mock_session.get.return_value.raise_for_status = Mock()
        
        client = CTFdAPIClient('http://localhost:8000', api_token='token')
        
        with patch.object(client, 'get_challenge') as mock_get:
            mock_get.side_effect = [
                CTFdChallenge(id=1, name='Challenge 1', category='crypto', value=100),
                CTFdChallenge(id=2, name='Challenge 2', category='web', value=200)
            ]
            
            challenges = client.list_challenges()
            
            assert len(challenges) == 2
            assert challenges[0].name == 'Challenge 1'
            assert challenges[1].category == 'web'
    
    def test_get_challenge(self, mock_session):
        """Test getting single challenge details."""
        mock_response = Mock()
        mock_response.json.return_value = {
            'data': {
                'id': 1,
                'name': 'Test Challenge',
                'category': 'crypto',
                'description': 'Test description',
                'value': 100,
                'state': 'visible',
                'type': 'standard',
                'files': [],
                'tags': [],
                'hints': [],
                'requirements': {}
            }
        }
        mock_response.raise_for_status = Mock()
        mock_session.get.return_value = mock_response
        
        client = CTFdAPIClient('http://localhost:8000', api_token='token')
        challenge = client.get_challenge(1)
        
        assert challenge is not None
        assert challenge.name == 'Test Challenge'
        assert challenge.category == 'crypto'
        assert challenge.value == 100
    
    def test_create_challenge(self, mock_session):
        """Test creating a new challenge."""
        mock_response = Mock()
        mock_response.json.return_value = {'data': {'id': 42}}
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        
        client = CTFdAPIClient('http://localhost:8000', api_token='token')
        
        challenge = CTFdChallenge(
            name='New Challenge',
            category='web',
            description='Test',
            value=150,
            flags=[{'content': 'flag{test}', 'type': 'static'}]
        )
        
        with patch.object(client, 'add_flag', return_value=True):
            challenge_id = client.create_challenge(challenge)
        
        assert challenge_id == 42
        mock_session.post.assert_called_once()
    
    def test_submit_flag_correct(self, mock_session):
        """Test submitting correct flag."""
        mock_response = Mock()
        mock_response.json.return_value = {
            'data': {
                'status': 'correct',
                'message': 'Correct!'
            }
        }
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        
        client = CTFdAPIClient('http://localhost:8000', api_token='token')
        submission = client.submit_flag(1, 'flag{correct}')
        
        assert submission.correct == True
        assert 'Correct' in submission.message
    
    def test_submit_flag_incorrect(self, mock_session):
        """Test submitting incorrect flag."""
        mock_response = Mock()
        mock_response.json.return_value = {
            'data': {
                'status': 'incorrect',
                'message': 'Incorrect'
            }
        }
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        
        client = CTFdAPIClient('http://localhost:8000', api_token='token')
        submission = client.submit_flag(1, 'flag{wrong}')
        
        assert submission.correct == False
    
    def test_export_challenges(self, mock_session):
        """Test exporting challenges to JSON."""
        client = CTFdAPIClient('http://localhost:8000', api_token='token')
        
        with patch.object(client, 'list_challenges') as mock_list:
            mock_list.return_value = [
                CTFdChallenge(id=1, name='Challenge 1', category='crypto', value=100)
            ]
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
                temp_file = f.name
            
            try:
                result = client.export_challenges(temp_file)
                assert result == True
                
                with open(temp_file, 'r') as f:
                    data = json.load(f)
                    assert len(data['challenges']) == 1
                    assert data['challenges'][0]['name'] == 'Challenge 1'
            finally:
                Path(temp_file).unlink()
    
    def test_health_check(self, mock_session):
        """Test CTFd health check."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        
        client = CTFdAPIClient('http://localhost:8000', api_token='token')
        result = client.health_check()
        
        assert result == True


class TestCTFdSolveSkill:
    """Test CTFd solve skill functionality."""
    
    @pytest.fixture
    def mock_client(self):
        """Create mock CTFd client."""
        with patch('skills.ctfd_solve.run.CTFdAPIClient') as mock:
            client = mock.return_value
            client.authenticated = True
            client.base_url = 'http://localhost:8000'
            yield client
    
    def test_solve_skill_list_mode(self, mock_client):
        """Test solve skill in list mode."""
        from skills.ctfd_solve.run import run
        
        mock_client.list_challenges.return_value = [
            CTFdChallenge(id=1, name='Challenge 1', category='crypto', value=100,
                         description='Test challenge', files=[], tags=[])
        ]
        
        result = run({
            'ctfd_url': 'http://localhost:8000',
            'api_token': 'test-token'
        })
        
        assert result['status'] is True
        assert result['result']['mode'] == 'list'
        assert len(result['result']['challenges']) == 1
    
    def test_solve_skill_no_credentials(self):
        """Test solve skill without credentials."""
        from skills.ctfd_solve.run import run
        
        result = run({
            'ctfd_url': 'http://localhost:8000'
        })
        
        assert result['status'] is False
        assert 'api_token' in result['summary'] or 'username' in result['summary']


class TestCTFdSetupSkill:
    """Test CTFd setup skill functionality."""
    
    def test_setup_quick_mode(self):
        """Test setup in quick mode."""
        from skills.ctfd_setup.run import run
        
        with patch('skills.ctfd_setup.run.CTFdSetup') as mock_setup:
            mock_instance = mock_setup.return_value
            mock_instance.execute.return_value = {
                'status': True,
                'ctfd_url': 'http://localhost:8000',
                'admin_credentials': {
                    'username': 'admin',
                    'password': 'admin'
                },
                'setup_log': [],
                'warnings': []
            }
            
            result = run({'deployment_mode': 'quick'})
            
            assert result['status'] is True
            assert 'admin_credentials' in result


class TestCTFdManageSkill:
    """Test CTFd manage skill functionality."""
    
    @pytest.fixture
    def mock_client(self):
        """Create mock CTFd client."""
        with patch('skills.ctfd_manage.run.CTFdAPIClient') as mock:
            client = mock.return_value
            client.authenticated = True
            yield client
    
    def test_manage_get_scoreboard(self, mock_client):
        """Test getting scoreboard."""
        from skills.ctfd_manage.run import run
        
        mock_client.get_scoreboard.return_value = [
            {'team': 'Team 1', 'score': 500},
            {'team': 'Team 2', 'score': 300}
        ]
        
        result = run({
            'ctfd_url': 'http://localhost:8000',
            'api_token': 'test-token',
            'action': 'get_scoreboard',
            'params': {'top_n': 10}
        })
        
        assert result['status'] is True
        assert len(result['result']['teams']) == 2
    
    def test_manage_delete_without_confirm(self):
        """Test destructive action without confirmation."""
        from skills.ctfd_manage.run import run
        
        result = run({
            'ctfd_url': 'http://localhost:8000',
            'api_token': 'test-token',
            'action': 'delete_challenge',
            'params': {'challenge_id': 1}
        })
        
        assert result['status'] is False
        assert 'confirm' in result['summary'].lower()
    
    def test_manage_unknown_action(self, mock_client):
        """Test unknown management action."""
        from skills.ctfd_manage.run import run
        
        result = run({
            'ctfd_url': 'http://localhost:8000',
            'api_token': 'test-token',
            'action': 'invalid_action',
            'params': {}
        })
        
        assert result['status'] is False
        assert 'unknown action' in result['summary'].lower()


class TestPurpleEngineCLI:
    """Test Purple Engine CLI."""
    
    def test_cli_help(self):
        """Test CLI help message."""
        from cli.main import PurpleEngineCLI
        
        cli = PurpleEngineCLI()
        
        # Should not raise
        with pytest.raises(SystemExit) as exc:
            cli.run(['--help'])
        
        assert exc.value.code == 0
    
    def test_cli_version(self):
        """Test CLI version."""
        from cli.main import PurpleEngineCLI
        
        cli = PurpleEngineCLI()
        
        with pytest.raises(SystemExit) as exc:
            cli.run(['--version'])
        
        assert exc.value.code == 0
    
    def test_cli_ctfd_solve_no_auth(self):
        """Test ctfd-solve without authentication."""
        from cli.main import PurpleEngineCLI
        
        cli = PurpleEngineCLI()
        result = cli.run(['ctfd-solve', 'http://localhost:8000'])
        
        assert result == 1  # Should fail


class TestDataModels:
    """Test CTFd data models."""
    
    def test_ctfd_challenge_creation(self):
        """Test CTFdChallenge dataclass."""
        challenge = CTFdChallenge(
            id=1,
            name='Test Challenge',
            category='crypto',
            description='Test',
            value=100
        )
        
        assert challenge.id == 1
        assert challenge.name == 'Test Challenge'
        assert isinstance(challenge.files, list)
        assert isinstance(challenge.flags, list)
    
    def test_ctfd_challenge_to_dict(self):
        """Test CTFdChallenge to_dict conversion."""
        challenge = CTFdChallenge(
            name='Test',
            category='web',
            value=150
        )
        
        data = challenge.to_dict()
        
        assert 'name' in data
        assert 'category' in data
        assert 'id' not in data  # Should be excluded
    
    def test_ctfd_submission_creation(self):
        """Test CTFdSubmission dataclass."""
        from datetime import datetime
        
        submission = CTFdSubmission(
            correct=True,
            message='Correct!',
            challenge_id=1,
            timestamp=datetime.now()
        )
        
        assert submission.correct == True
        assert submission.challenge_id == 1


# Run tests
if __name__ == '__main__':
    pytest.main([__file__, '-v'])
