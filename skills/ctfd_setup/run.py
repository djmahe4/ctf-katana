"""
Purple Engine - CTFd Setup Skill Implementation

Automated deployment and configuration of complete CTFd instances.
Orchestrates Docker Compose, initial setup, plugin installation, and challenge imports.
"""

import json
import os
import sys
import subprocess
import time
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import logging
import re

# Add project root for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Import CTFd API client from server utils
from server.utils.ctfd_client import CTFdAPIClient, CTFdChallenge

logger = logging.getLogger(__name__)


class CTFdSetup:
    """
    Automated CTFd deployment and configuration orchestrator.
    
    Handles complete lifecycle from Docker deployment to challenge imports.
    """
    
    def __init__(self,
                 deployment_mode: str = "quick",
                 admin_username: str = "admin",
                 admin_password: str = "admin",
                 admin_email: str = "admin@ctfd.local",
                 ctf_name: str = "Purple Engine CTF",
                 ctf_description: str = "Powered by Purple Engine - Agentic AI CTF Platform",
                 user_mode: str = "teams",
                 challenge_visibility: str = "private",
                 registration_visibility: str = "public",
                 start_time: str = None,
                 end_time: str = None,
                 install_plugins: List[str] = None,
                 theme: str = "core",
                 challenge_packs: List[str] = None,
                 docker_compose_dir: str = None,
                 wait_timeout: int = 60,
                 auto_backup: bool = True):
        """Initialize CTFd setup orchestrator."""
        
        self.deployment_mode = deployment_mode
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.admin_email = admin_email
        self.ctf_name = ctf_name
        self.ctf_description = ctf_description
        self.user_mode = user_mode
        self.challenge_visibility = challenge_visibility
        self.registration_visibility = registration_visibility
        self.start_time = start_time
        self.end_time = end_time
        self.install_plugins = install_plugins or []
        self.theme = theme
        self.challenge_packs = challenge_packs or []
        self.wait_timeout = wait_timeout
        self.auto_backup = auto_backup
        
        # Determine docker-compose directory
        if docker_compose_dir:
            self.docker_compose_dir = Path(docker_compose_dir)
        else:
            # Default to configs/ctfd relative to repo root
            repo_root = Path(__file__).parent.parent.parent.parent
            self.docker_compose_dir = repo_root / "configs" / "ctfd"
        
        self.ctfd_url = "http://localhost:8000"
        self.setup_log = []
        self.warnings = []
        
    def log(self, message: str, level: str = "info"):
        """Add message to setup log."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.setup_log.append(log_entry)
        
        if level == "info":
            logger.info(message)
        elif level == "warning":
            logger.warning(message)
            self.warnings.append(message)
        elif level == "error":
            logger.error(message)
    
    def run_command(self, cmd: str, shell: bool = True, cwd: str = None) -> Tuple[int, str, str]:
        """Execute shell command and return (returncode, stdout, stderr)."""
        try:
            result = subprocess.run(
                cmd,
                shell=shell,
                capture_output=True,
                text=True,
                cwd=cwd or self.docker_compose_dir,
                timeout=120
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timeout"
        except Exception as e:
            return -1, "", str(e)
    
    def check_docker(self) -> bool:
        """Verify Docker is installed and running."""
        self.log("Checking Docker availability...")
        
        rc, stdout, stderr = self.run_command("docker --version")
        if rc != 0:
            self.log("Docker not found or not running", "error")
            return False
        
        self.log(f"Docker check: OK - {stdout.strip()}")
        
        # Check Docker daemon is running
        rc, stdout, stderr = self.run_command("docker ps")
        if rc != 0:
            self.log("Docker daemon not running", "error")
            return False
        
        self.log("Docker daemon: Running")
        return True
    
    def check_docker_compose(self) -> bool:
        """Verify Docker Compose is available."""
        self.log("Checking Docker Compose...")
        
        # Try docker-compose (standalone)
        rc, stdout, stderr = self.run_command("docker-compose --version")
        if rc == 0:
            self.log(f"Docker Compose check: OK - {stdout.strip()}")
            return True
        
        # Try docker compose (plugin)
        rc, stdout, stderr = self.run_command("docker compose version")
        if rc == 0:
            self.log(f"Docker Compose check: OK - {stdout.strip()}")
            return True
        
        self.log("Docker Compose not found", "error")
        return False
    
    def check_port_available(self, port: int = 8000) -> bool:
        """Check if port is available."""
        import socket
        
        self.log(f"Checking port {port} availability...")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('127.0.0.1', port))
                self.log(f"Port {port}: Available")
                return True
            except OSError:
                self.log(f"Port {port}: Already in use", "warning")
                return False
    
    def prepare_env_file(self):
        """Create and configure .env file."""
        self.log("Preparing environment configuration...")
        
        env_file = self.docker_compose_dir / ".env"
        env_example = self.docker_compose_dir / ".env.example"
        
        # Copy from example if .env doesn't exist
        if not env_file.exists() and env_example.exists():
            shutil.copy(env_example, env_file)
            self.log("Created .env from .env.example")
        
        # Update .env with provided values
        if env_file.exists():
            content = env_file.read_text()
            
            # Update credentials
            content = re.sub(r'CTFD_ADMIN_USERNAME=.*', f'CTFD_ADMIN_USERNAME={self.admin_username}', content)
            content = re.sub(r'CTFD_ADMIN_PASSWORD=.*', f'CTFD_ADMIN_PASSWORD={self.admin_password}', content)
            content = re.sub(r'CTFD_ADMIN_EMAIL=.*', f'CTFD_ADMIN_EMAIL={self.admin_email}', content)
            
            env_file.write_text(content)
            self.log("Updated .env with provided credentials")
        else:
            self.log(".env file not found, using docker-compose defaults", "warning")
    
    def deploy_docker_stack(self) -> bool:
        """Deploy CTFd Docker Compose stack."""
        self.log("Deploying Docker Compose stack...")
        
        # Determine docker-compose command
        rc, _, _ = self.run_command("docker-compose --version")
        if rc == 0:
            dc_cmd = "docker-compose"
        else:
            dc_cmd = "docker compose"
        
        # Deploy stack
        rc, stdout, stderr = self.run_command(f"{dc_cmd} up -d")
        
        if rc != 0:
            self.log(f"Docker Compose up failed: {stderr}", "error")
            return False
        
        self.log("Docker Compose up: Success")
        return True
    
    def wait_for_ctfd(self) -> bool:
        """Wait for CTFd to be healthy."""
        self.log(f"Waiting for CTFd to be ready (timeout: {self.wait_timeout}s)...")
        
        import requests
        
        start_time = time.time()
        while time.time() - start_time < self.wait_timeout:
            try:
                response = requests.get(f"{self.ctfd_url}/healthcheck", timeout=5)
                if response.status_code == 200:
                    self.log("CTFd health check: Passed")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            time.sleep(2)
        
        self.log("CTFd health check: Timeout", "error")
        return False
    
    def perform_initial_setup(self) -> bool:
        """Execute CTFd initial setup via web interface."""
        self.log("Performing initial CTFd setup...")
        
        import requests
        from bs4 import BeautifulSoup
        
        session = requests.Session()
        
        # Check if setup is needed
        try:
            response = session.get(f"{self.ctfd_url}/setup", timeout=10)
            
            # If redirects to /, already configured
            if response.url.endswith('/'):
                self.log("CTFd already configured, skipping initial setup")
                return True
            
            # Extract nonce
            soup = BeautifulSoup(response.text, 'html.parser')
            nonce_input = soup.find('input', {'name': 'nonce'})
            
            if not nonce_input:
                self.log("Could not extract CSRF nonce", "error")
                return False
            
            nonce = nonce_input.get('value', '')
            
            # Submit setup form
            setup_data = {
                'ctf_name': self.ctf_name,
                'ctf_description': self.ctf_description,
                'name': self.admin_username,
                'email': self.admin_email,
                'password': self.admin_password,
                'user_mode': self.user_mode,
                'nonce': nonce
            }
            
            response = session.post(
                f"{self.ctfd_url}/setup",
                data=setup_data,
                allow_redirects=False
            )
            
            if response.status_code in [302, 200]:
                self.log("Initial setup: Completed")
                return True
            else:
                self.log(f"Setup failed with status {response.status_code}", "error")
                return False
                
        except Exception as e:
            self.log(f"Setup error: {e}", "error")
            return False
    
    def configure_event_settings(self, client: CTFdAPIClient) -> bool:
        """Configure event-specific settings."""
        self.log("Configuring event settings...")
        
        try:
            # Time-based configuration
            if self.start_time:
                client.update_config('start', self.start_time)
                self.log(f"Set start time: {self.start_time}")
            
            if self.end_time:
                client.update_config('end', self.end_time)
                self.log(f"Set end time: {self.end_time}")
            
            # Visibility settings
            client.update_config('challenge_visibility', self.challenge_visibility)
            self.log(f"Challenge visibility: {self.challenge_visibility}")
            
            client.update_config('registration_visibility', self.registration_visibility)
            self.log(f"Registration visibility: {self.registration_visibility}")
            
            return True
            
        except Exception as e:
            self.log(f"Event configuration error: {e}", "warning")
            return False
    
    def install_plugin(self, plugin_name: str) -> bool:
        """Install a CTFd plugin."""
        self.log(f"Installing plugin: {plugin_name}...")
        
        plugin_urls = {
            'CTFd-Whale': 'https://github.com/frankli0324/CTFd-Whale.git'
        }
        
        if plugin_name not in plugin_urls:
            self.log(f"Unknown plugin: {plugin_name}", "warning")
            return False
        
        # Clone plugin into container
        cmd = f"""docker exec purple_ctfd bash -c '
            cd /opt/CTFd/CTFd/plugins && \
            git clone --depth 1 {plugin_urls[plugin_name]} {plugin_name} && \
            if [ -f {plugin_name}/requirements.txt ]; then \
                pip install -r {plugin_name}/requirements.txt; \
            fi
        '"""
        
        rc, stdout, stderr = self.run_command(cmd)
        
        if rc == 0:
            self.log(f"Plugin {plugin_name}: Installed")
            
            # Restart CTFd to load plugin
            self.run_command("docker-compose restart ctfd")
            time.sleep(5)  # Wait for restart
            
            return True
        else:
            self.log(f"Plugin {plugin_name} installation failed: {stderr}", "warning")
            return False
    
    def import_challenge_pack(self, pack_path: str, client: CTFdAPIClient) -> int:
        """Import challenges from a pack."""
        self.log(f"Importing challenge pack: {pack_path}...")
        
        pack_file = Path(pack_path)
        
        if not pack_file.exists():
            self.log(f"Challenge pack not found: {pack_path}", "warning")
            return 0
        
        try:
            if pack_file.suffix == '.json':
                # JSON export format
                count = client.import_challenges(str(pack_file))
                self.log(f"Imported {count} challenges from {pack_file.name}")
                return count
            else:
                self.log(f"Unsupported pack format: {pack_file.suffix}", "warning")
                return 0
                
        except Exception as e:
            self.log(f"Import error: {e}", "warning")
            return 0
    
    def create_backup(self) -> Optional[str]:
        """Create backup of CTFd instance."""
        self.log("Creating backup...")
        
        backup_dir = self.docker_compose_dir.parent.parent / "backups"
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = backup_dir / f"ctfd_backup_{timestamp}.sql"
        
        # Backup database
        cmd = f"docker exec purple_ctfd_db mysqldump -u ctfd -pctfd ctfd > {backup_file}"
        rc, stdout, stderr = self.run_command(cmd)
        
        if rc == 0 and backup_file.exists():
            self.log(f"Backup created: {backup_file}")
            return str(backup_file)
        else:
            self.log("Backup failed", "warning")
            return None
    
    def execute(self) -> Dict[str, Any]:
        """Execute complete setup workflow."""
        self.log(f"Starting CTFd setup in {self.deployment_mode} mode...")
        
        # Phase 1: Pre-flight checks
        if not self.check_docker():
            return {'status': 'failed', 'error': 'Docker not available', 'setup_log': self.setup_log}
        
        if not self.check_docker_compose():
            return {'status': 'failed', 'error': 'Docker Compose not available', 'setup_log': self.setup_log}
        
        port_available = self.check_port_available(8000)
        if not port_available:
            self.warnings.append("Port 8000 in use - existing CTFd instance may be running")
        
        # Phase 2: Prepare environment
        self.prepare_env_file()
        
        # Phase 3: Deploy Docker stack
        if not self.deploy_docker_stack():
            return {'status': 'failed', 'error': 'Docker deployment failed', 'setup_log': self.setup_log}
        
        # Phase 4: Wait for health
        if not self.wait_for_ctfd():
            return {'status': 'failed', 'error': 'CTFd health check timeout', 'setup_log': self.setup_log}
        
        # Phase 5: Initial setup
        if not self.perform_initial_setup():
            return {'status': 'failed', 'error': 'Initial setup failed', 'setup_log': self.setup_log}
        
        # Phase 6: Configure via API
        try:
            client = CTFdAPIClient(
                base_url=self.ctfd_url,
                username=self.admin_username,
                password=self.admin_password
            )
            
            if not client.authenticated:
                self.log("API authentication failed", "warning")
        except Exception as e:
            self.log(f"API client error: {e}", "warning")
            client = None
        
        # Phase 7: Event configuration
        if client:
            self.configure_event_settings(client)
        
        # Phase 8: Install plugins
        plugins_installed = []
        plugins_failed = []
        
        for plugin in self.install_plugins:
            if self.install_plugin(plugin):
                plugins_installed.append(plugin)
            else:
                plugins_failed.append(plugin)
        
        # Phase 9: Import challenges
        challenges_imported = 0
        
        if client:
            for pack in self.challenge_packs:
                challenges_imported += self.import_challenge_pack(pack, client)
        
        # Phase 10: Backup
        backup_path = None
        if self.auto_backup:
            backup_path = self.create_backup()
        
        # Security warnings
        if self.admin_password == "admin":
            self.warnings.append("Default admin password used - CHANGE IN PRODUCTION")
        
        if not self.ctfd_url.startswith('https'):
            self.warnings.append("HTTP only - configure HTTPS for production deployment")
        
        # Build result
        result = {
            'status': 'success',
            'ctfd_url': self.ctfd_url,
            'admin_credentials': {
                'username': self.admin_username,
                'password': self.admin_password,
                'email': self.admin_email
            },
            'api_token': None,  # Would need to generate via UI
            'event_config': {
                'ctf_name': self.ctf_name,
                'user_mode': self.user_mode,
                'challenge_visibility': self.challenge_visibility,
                'start_time': self.start_time,
                'end_time': self.end_time
            },
            'plugins_installed': plugins_installed,
            'plugins_failed': plugins_failed,
            'theme': self.theme,
            'challenges_imported': challenges_imported,
            'challenges_failed': len(self.challenge_packs) - (challenges_imported > 0),
            'backup_path': backup_path,
            'setup_log': self.setup_log,
            'next_steps': [
                f"Access CTFd at {self.ctfd_url}",
                f"Login with username: {self.admin_username}",
                "Change default password in production",
                "Configure email settings for password resets",
                "Use purple-engine ctfd-solve to test challenges"
            ],
            'warnings': self.warnings
        }
        
        if plugins_failed or challenges_imported == 0 and self.challenge_packs:
            result['status'] = 'partial'
        
        self.log("CTFd setup completed!")
        return result


def run(inputs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for ctfd_setup skill.
    
    Args:
        inputs: Dictionary with setup parameters
        
    Returns:
        Dictionary with setup results
    """
    try:
        setup = CTFdSetup(
            deployment_mode=inputs.get('deployment_mode', 'quick'),
            admin_username=inputs.get('admin_username', 'admin'),
            admin_password=inputs.get('admin_password', 'admin'),
            admin_email=inputs.get('admin_email', 'admin@ctfd.local'),
            ctf_name=inputs.get('ctf_name', 'Purple Engine CTF'),
            ctf_description=inputs.get('ctf_description', 'Powered by Purple Engine - Agentic AI CTF Platform'),
            user_mode=inputs.get('user_mode', 'teams'),
            challenge_visibility=inputs.get('challenge_visibility', 'private'),
            registration_visibility=inputs.get('registration_visibility', 'public'),
            start_time=inputs.get('start_time'),
            end_time=inputs.get('end_time'),
            install_plugins=inputs.get('install_plugins', []),
            theme=inputs.get('theme', 'core'),
            challenge_packs=inputs.get('challenge_packs', []),
            docker_compose_dir=inputs.get('docker_compose_dir'),
            wait_timeout=inputs.get('wait_timeout', 60),
            auto_backup=inputs.get('auto_backup', True)
        )
        
        result = setup.execute()
        return result
        
    except Exception as e:
        logger.error(f"CTFd setup error: {e}", exc_info=True)
        return {
            'status': 'error',
            'error': str(e)
        }


if __name__ == '__main__':
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    test_inputs = {
        'deployment_mode': 'quick'
    }
    
    result = run(test_inputs)
    print(json.dumps(result, indent=2))
