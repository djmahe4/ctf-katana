import re
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class GitDiffParser:
    """
    Utility to parse and filter git diffs/patches.
    Extracts changes for specific files to focus intelligence mining.
    """
    
    def __init__(self):
        # Regex to split a patch into individual file diffs
        # Matches 'diff --git a/path b/path' or '--- a/path\n+++ b/path'
        self.file_split_pattern = re.compile(r'(?=diff --git a/.*? b/.*?|--- a/.*?|Index: .*)', re.MULTILINE)

    def parse_patch(self, patch_text: str, filter_files: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Parses a raw patch/diff text and returns a map of {filename: diff_content}.
        If filter_files is provided, only returns diffs for those files.
        """
        if not patch_text:
            return {}

        # Split by file headers
        chunks = self.file_split_pattern.split(patch_text)
        file_diffs = {}

        for chunk in chunks:
            if not chunk.strip():
                continue
                
            # Extract filename from chunk
            # Patterns: 
            # diff --git a/path/to/file.c b/path/to/file.c
            # --- a/path/to/file.c
            # +++ b/path/to/file.c
            # Index: path/to/file.c
            
            filename = None
            
            # Try '+++ b/' or '+++ ' (the destination file)
            match = re.search(r'^\+\+\+ (?:b/)?([^\t\n\r]+)', chunk, re.MULTILINE)
            if not match:
                # Try 'diff --git a/...'
                match = re.search(r'^diff --git a/.*? b/(.*)', chunk, re.MULTILINE)
            
            if match:
                filename = match.group(1).strip()
                # Clean up if there are multiple spaces or tabs after filename
                filename = filename.split('\t')[0].split('  ')[0].strip()

            if filename:
                # If we have a filter, check if this file is in it (partial match supported)
                if filter_files:
                    is_match = False
                    for f in filter_files:
                        if f in filename or filename in f:
                            is_match = True
                            break
                    if not is_match:
                        continue
                
                file_diffs[filename] = chunk.strip()

        return file_diffs

    def analyze_logic_change(self, file_diffs: Dict[str, str]) -> str:
        """
        Performs a basic heuristic analysis of the changes.
        Identifies if it's a security-sensitive change (e.g., bounds check, null check).
        """
        summary = []
        for filename, diff in file_diffs.items():
            checks = []
            if re.search(r'\+.*if\s*\(.*==\s*NULL', diff): checks.append("Null check")
            if re.search(r'\+.*if\s*\(.*>\s*.*size', diff, re.I): checks.append("Bounds check")
            if re.search(r'\+.*mem(cpy|set|move)', diff): checks.append("Memory operation")
            if re.search(r'\+.*(free|kfree|delete)', diff): checks.append("Deallocation")
            if re.search(r'\+.*(lock|mutex)', diff): checks.append("Concurrency primitive")
            
            check_str = f" [{', '.join(checks)}]" if checks else ""
            summary.append(f"- {filename}: {len(diff.splitlines())} lines changed{check_str}")
            
        return "\n".join(summary)

    def get_patch_url(self, repo_url: str, commit_hash: str) -> Optional[str]:
        """Constructs a raw patch URL for common git hosting platforms."""
        if not repo_url or not commit_hash:
            return None
            
        url = repo_url.rstrip("/")
        
        # GitHub
        if "github.com" in url:
            if "/blob/" in url:
                url = url.split("/blob/")[0]
            return f"{url}/commit/{commit_hash}.patch"
        
        # GitLab
        if "gitlab.com" in url:
            return f"{url}/-/commit/{commit_hash}.patch"
        
        # Kernel.org
        if "git.kernel.org" in url:
            # Handle standard kernel.org URLs
            return f"{url}/patch/?id={commit_hash}"
            
        return None
