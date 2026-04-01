"""
Purple Engine - Main CLI Entrypoint

Command-line interface for Purple Engine with rich TUI support.
Provides access to all Purple Engine functionality:
- CTFd deployment and management
- Challenge solving
- Research agent (Phase 3)
- Challenge generation (Phase 3)
- Purple team simulation (Phase 5)
"""

import sys
import os
import argparse
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class PurpleEngineCLI:
    """
    Purple Engine command-line interface.
    
    Provides unified access to all Purple Engine capabilities.
    """
    
    def __init__(self):
        self.parser = self._build_parser()
    
    def _build_parser(self) -> argparse.ArgumentParser:
        """Build argument parser with all commands."""
        parser = argparse.ArgumentParser(
            prog='purple-engine',
            description='Purple Engine - 100% Local Agentic AI CTF Platform',
            epilog='Powered by Ollama | No API Keys Required'
        )
        
        parser.add_argument(
            '--version',
            action='version',
            version='Purple Engine v0.1.0-alpha'
        )
        
        parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='Enable verbose logging'
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        
        # ==================== CTFd Commands ====================
        
        # ctfd-setup command
        setup_parser = subparsers.add_parser(
            'ctfd-setup',
            help='Deploy and configure CTFd instance'
        )
        setup_parser.add_argument(
            '--mode',
            choices=['quick', 'custom'],
            default='quick',
            help='Deployment mode (default: quick)'
        )
        setup_parser.add_argument(
            '--admin-user',
            default='admin',
            help='Admin username (default: admin)'
        )
        setup_parser.add_argument(
            '--admin-pass',
            default='admin',
            help='Admin password (default: admin - CHANGE IN PROD!)'
        )
        setup_parser.add_argument(
            '--admin-email',
            default='admin@ctfd.local',
            help='Admin email'
        )
        setup_parser.add_argument(
            '--ctf-name',
            default='Purple Engine CTF',
            help='CTF event name'
        )
        
        # ctfd-solve command
        solve_parser = subparsers.add_parser(
            'ctfd-solve',
            help='Autonomously solve CTFd challenges'
        )
        solve_parser.add_argument(
            'ctfd_url',
            help='CTFd instance URL (e.g., http://localhost:8000)'
        )
        solve_parser.add_argument(
            '--token',
            help='CTFd API token'
        )
        solve_parser.add_argument(
            '--username',
            help='CTFd username (alternative to token)'
        )
        solve_parser.add_argument(
            '--password',
            help='CTFd password (alternative to token)'
        )
        solve_parser.add_argument(
            '--challenge-id',
            type=int,
            help='Specific challenge ID to solve'
        )
        solve_parser.add_argument(
            '--challenge-name',
            help='Specific challenge name to solve'
        )
        solve_parser.add_argument(
            '--category',
            choices=['crypto', 'stego', 'forensics', 'web', 'pwn', 'reversing', 'recon', 'misc'],
            help='Filter by category'
        )
        solve_parser.add_argument(
            '--no-submit',
            action='store_true',
            help='Disable auto-flag submission'
        )
        solve_parser.add_argument(
            '--output-dir',
            default='./ctfd_output',
            help='Output directory for write-ups (default: ./ctfd_output)'
        )
        
        # ctfd-manage command
        manage_parser = subparsers.add_parser(
            'ctfd-manage',
            help='Manage CTFd instance lifecycle'
        )
        manage_parser.add_argument(
            'action',
            help='Management action (e.g., create_challenge, get_scoreboard)'
        )
        manage_parser.add_argument(
            '--ctfd-url',
            default='http://localhost:8000',
            help='CTFd instance URL'
        )
        manage_parser.add_argument(
            '--token',
            help='CTFd API token'
        )
        manage_parser.add_argument(
            '--params',
            type=json.loads,
            default='{}',
            help='Action parameters as JSON string'
        )
        
        # ==================== Research Commands (Phase 3) ====================
        
        research_parser = subparsers.add_parser(
            'research-agent',
            help='[Phase 3] Run autonomous vulnerability research'
        )
        research_parser.add_argument(
            '--mode',
            choices=['scan', 'discover', 'generate'],
            default='scan',
            help='Research mode'
        )
        
        # ==================== Challenge Generation (Phase 3) ====================
        
        generate_parser = subparsers.add_parser(
            'generate-challenge',
            help='[Phase 3] Generate CTF challenge'
        )
        generate_parser.add_argument(
            '--category',
            required=True,
            help='Challenge category'
        )
        generate_parser.add_argument(
            '--difficulty',
            choices=['easy', 'medium', 'hard'],
            default='medium',
            help='Challenge difficulty'
        )
        
        # ==================== Write-up Generation ====================
        
        writeup_parser = subparsers.add_parser(
            'writeup',
            help='Generate challenge write-up'
        )
        writeup_parser.add_argument(
            'challenge_name',
            help='Challenge name'
        )
        writeup_parser.add_argument(
            '--solving-log',
            required=True,
            help='Path to solving log JSON'
        )
        
        # ==================== Purple Team (Phase 5) ====================
        
        purple_parser = subparsers.add_parser(
            'purple-team',
            help='[Phase 5] Run purple team simulation'
        )
        purple_parser.add_argument(
            '--target',
            required=True,
            help='Target system or challenge'
        )
        
        return parser
    
    # ==================== Command Handlers ====================
    
    def cmd_ctfd_setup(self, args) -> int:
        """Handle ctfd-setup command."""
        from skills.ctfd.setup.run import run
        
        print("🚀 Purple Engine - CTFd Setup")
        print("=" * 50)
        
        inputs = {
            'deployment_mode': args.mode,
            'admin_username': args.admin_user,
            'admin_password': args.admin_pass,
            'admin_email': args.admin_email,
            'ctf_name': args.ctf_name
        }
        
        print(f"\nDeploying CTFd in {args.mode} mode...")
        print(f"Admin: {args.admin_user} / {args.admin_email}")
        
        result = run(inputs)
        
        if result['status'] == 'success':
            print("\n✓ CTFd deployment successful!")
            print(f"\n📍 Access CTFd at: {result['ctfd_url']}")
            print(f"👤 Username: {result['admin_credentials']['username']}")
            print(f"🔑 Password: {result['admin_credentials']['password']}")
            
            if result.get('warnings'):
                print("\n⚠️  Warnings:")
                for warning in result['warnings']:
                    print(f"  - {warning}")
            
            print("\n📋 Next steps:")
            for step in result.get('next_steps', []):
                print(f"  • {step}")
            
            return 0
        else:
            print(f"\n✗ CTFd deployment failed: {result.get('error', 'Unknown error')}")
            if result.get('setup_log'):
                print("\nSetup log:")
                for log_entry in result['setup_log']:
                    print(f"  {log_entry}")
            return 1
    
    def cmd_ctfd_solve(self, args) -> int:
        """Handle ctfd-solve command."""
        from skills.ctfd.solve.run import run
        
        print("🎯 Purple Engine - CTFd Challenge Solver")
        print("=" * 50)
        
        # Validate authentication
        if not args.token and not (args.username and args.password):
            print("✗ Error: Must provide --token or --username + --password")
            return 1
        
        inputs = {
            'ctfd_url': args.ctfd_url,
            'api_token': args.token,
            'username': args.username,
            'password': args.password,
            'challenge_id': args.challenge_id,
            'challenge_name': args.challenge_name,
            'category': args.category,
            'auto_submit': not args.no_submit,
            'output_dir': args.output_dir
        }
        
        # Remove None values
        inputs = {k: v for k, v in inputs.items() if v is not None}
        
        print(f"\n🔗 Connecting to: {args.ctfd_url}")
        
        result = run(inputs)
        
        if result['status'] == 'success':
            if result['mode'] == 'list':
                # List mode
                print(f"\n📋 Found {result['total_challenges']} challenges:")
                for challenge in result['challenges']:
                    print(f"  [{challenge['category']}] {challenge['name']} - {challenge['value']}pts")
                return 0
            
            elif result['mode'] == 'solve':
                # Solve mode
                solve_result = result['result']
                
                if solve_result['status'] == 'solved':
                    print(f"\n✓ Challenge solved: {solve_result['challenge_name']}")
                    print(f"🚩 Flag: {solve_result['flag']}")
                    
                    if solve_result.get('submitted'):
                        print(f"✓ Flag submitted successfully (+{solve_result['value']}pts)")
                    
                    if solve_result.get('writeup_path'):
                        print(f"📄 Write-up: {solve_result['writeup_path']}")
                    
                    print(f"\n⏱️  Solve time: {solve_result['solve_time_seconds']:.1f}s")
                    
                    return 0
                else:
                    print(f"\n⚠️  Challenge attempted but not solved: {solve_result['challenge_name']}")
                    print(f"Status: {solve_result['status']}")
                    return 1
        else:
            print(f"\n✗ Error: {result.get('message', 'Unknown error')}")
            return 1
    
    def cmd_ctfd_manage(self, args) -> int:
        """Handle ctfd-manage command."""
        from skills.ctfd.manage.run import run
        
        print(f"🛡️  Purple Engine - CTFd Manage: {args.action}")
        print("=" * 50)
        
        inputs = {
            'ctfd_url': args.ctfd_url,
            'api_token': args.token,
            'action': args.action,
            'params': args.params
        }
        
        result = run(inputs)
        
        if result['status'] in ['success', 'partial']:
            print(f"\n✓ {result['message']}")
            
            if result.get('result'):
                print(f"\nResult:")
                print(json.dumps(result['result'], indent=2))
            
            if result.get('warnings'):
                print("\n⚠️  Warnings:")
                for warning in result['warnings']:
                    print(f"  - {warning}")
            
            return 0
        else:
            print(f"\n✗ {result['message']}")
            return 1
    
    def cmd_not_implemented(self, args, phase: str) -> int:
        """Handle not-yet-implemented commands."""
        print(f"\n⚠️  This command is planned for {phase}")
        print("Run 'purple-engine --help' for available commands")
        return 1
    
    # ==================== Main Execution ====================
    
    def run(self, argv: Optional[List[str]] = None) -> int:
        """Execute CLI with given arguments."""
        args = self.parser.parse_args(argv)
        
        # Set logging level
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Route to command handler
        if args.command == 'ctfd-setup':
            return self.cmd_ctfd_setup(args)
        
        elif args.command == 'ctfd-solve':
            return self.cmd_ctfd_solve(args)
        
        elif args.command == 'ctfd-manage':
            return self.cmd_ctfd_manage(args)
        
        elif args.command == 'research-agent':
            return self.cmd_not_implemented(args, "Phase 3: Research & RAG")
        
        elif args.command == 'generate-challenge':
            return self.cmd_not_implemented(args, "Phase 3: Research & RAG")
        
        elif args.command == 'writeup':
            return self.cmd_not_implemented(args, "Phase 3: Research & RAG")
        
        elif args.command == 'purple-team':
            return self.cmd_not_implemented(args, "Phase 5: Production")
        
        else:
            self.parser.print_help()
            return 0


def main():
    """Main entry point."""
    try:
        cli = PurpleEngineCLI()
        sys.exit(cli.run())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n✗ Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
