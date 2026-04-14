"""
Purple Engine - CTFd API Client Bridge
Redirects to the central implementation in server/utils/ctfd_client.py
"""

import sys
from pathlib import Path

# Add project root to sys.path to allow importing from server.utils
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from server.utils.ctfd_client import CTFdAPIClient, CTFdChallenge, CTFdSubmission
except ImportError:
    # Fallback for when server.utils is not yet in path or structured differently
    # This might happen in some testing environments
    raise ImportError("Could not find server.utils.ctfd_client. Ensure project root is in PYTHONPATH.")
