"""
Purple Engine CLI - Main Entry Point

Provides a unified command-line interface for the Purple Engine ecosystem.
"""

import sys
import argparse
import logging
from typing import List, Optional

# Version should ideally be imported from a central location
__version__ = "1.0.0"

logger = logging.getLogger(__name__)

class PurpleEngineCLI:
    """
    Main CLI class for Purple Engine.
    Handles command parsing and dispatching to relevant skills and agents.
    """

    def __init__(self):
        self.parser = self._setup_parser()

    def _setup_parser(self) -> argparse.ArgumentParser:
        """Initialize the argument parser with subcommands."""
        parser = argparse.ArgumentParser(
            description="Purple Engine: Agentic CTF Orchestrator",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument('-v', '--version', action='version', version=f'Purple Engine v{__version__}')
        
        subparsers = parser.add_subparsers(dest='command', help='Commands')

        # ctfd-solve command
        solve_parser = subparsers.add_parser('ctfd-solve', help='Autonomously solve CTFd challenges')
        solve_parser.add_argument('url', help='CTFd instance URL')
        solve_parser.add_argument('--token', help='CTFd API token')
        solve_parser.add_argument('--user', help='CTFd username')
        solve_parser.add_argument('--password', help='CTFd password')
        solve_parser.add_argument('--id', type=int, help='Specific challenge ID to solve')
        solve_parser.add_argument('--name', help='Specific challenge name to solve')

        # katana-server command (convenience wrapper)
        server_parser = subparsers.add_parser('server', help='Start the MCP server')
        server_parser.add_argument('--port', type=int, default=8000, help='Port to run the server on')

        return parser

    def run(self, args: Optional[List[str]] = None) -> int:
        """
        Execute the CLI with provided arguments.
        
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        if args is None:
            args = sys.argv[1:]

        # Handle empty arguments (show help)
        if not args:
            self.parser.print_help()
            return 0

        try:
            parsed_args = self.parser.parse_args(args)
            
            if parsed_args.command == 'ctfd-solve':
                return self._handle_ctfd_solve(parsed_args)
            elif parsed_args.command == 'server':
                return self._handle_server(parsed_args)
            
            return 0
        except SystemExit as e:
            # Re-raise SystemExit for parser help/version
            raise e
        except Exception as e:
            print(f"Error: {e}")
            return 1

    def _handle_ctfd_solve(self, args: argparse.Namespace) -> int:
        """Dispatch to CTFd solve skill."""
        try:
            from skills.ctfd_solve.run import run
            
            params = {
                'ctfd_url': args.url,
                'api_token': args.token,
                'username': args.user,
                'password': args.password,
                'challenge_id': args.id,
                'challenge_name': args.name
            }
            # Remove None values
            params = {k: v for k, v in params.items() if v is not None}
            
            result = run(params)
            if result.get('status') is True:
                print(f"Success: {result.get('summary')}")
                return 0
            else:
                print(f"Failure: {result.get('summary')}")
                return 1
        except ImportError:
            print("Error: CTFd solve skill not found.")
            return 1
        except Exception as e:
            print(f"Error during solve execution: {e}")
            return 1

    def _handle_server(self, args: argparse.Namespace) -> int:
        """Launch the MCP server."""
        try:
            from server.mcp_server import main as server_main
            # Note: server_main might not take port yet, but we provide it for future proofing
            server_main()
            return 0
        except ImportError:
            print("Error: MCP server module not found.")
            return 1

def main():
    """CLI Entry point."""
    cli = PurpleEngineCLI()
    sys.exit(cli.run())

if __name__ == '__main__':
    main()
