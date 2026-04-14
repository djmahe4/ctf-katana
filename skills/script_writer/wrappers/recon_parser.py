"""ReconParser – correlates tool outputs from the Master Recon Pipeline.

Parses ``alive.txt``, ``ports.txt``, and ``nuclei.txt`` (or their equivalents
in JSONL/grep format) into a normalised findings dictionary compatible with
the ``ReportGenerator``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Generator, List

logger = logging.getLogger(__name__)


class ReconParser:
    """Parses outputs from the Master Recon Pipeline into actionable JSON.

    Parameters
    ----------
    workspace:
        Directory path that contains the tool output files.
    """

    def __init__(self, workspace: str) -> None:
        self.workspace = Path(workspace)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate_findings(self) -> Dict[str, Any]:
        """Merge alive.txt, ports.txt, and nuclei.txt into a master dataset.

        Returns
        -------
        dict
            ``{"hosts": [...], "ports": [...], "vulnerabilities": [...]}``
        """
        results: Dict[str, Any] = {
            "hosts": [],
            "ports": [],
            "vulnerabilities": [],
        }

        results["hosts"] = self._read_lines("alive.txt")
        results["ports"] = self._read_lines("ports.txt")

        nuclei_path = self.workspace / "nuclei.txt"
        if nuclei_path.exists():
            for entry in self._parse_nuclei(nuclei_path):
                results["vulnerabilities"].append(entry)

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_lines(self, filename: str) -> List[str]:
        """Read a text file and return non-blank stripped lines."""
        path = self.workspace / filename
        if not path.exists():
            logger.debug("%s not found in workspace %s", filename, self.workspace)
            return []
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return [line.strip() for line in fh if line.strip()]

    @staticmethod
    def _parse_nuclei(path: Path) -> Generator[Dict[str, Any], None, None]:
        """Yield parsed vulnerability records from a nuclei output file.

        Handles both:
        * Standard grep/text format:  ``[template] [protocol] [severity] target``
        * JSONL format:               one JSON object per line
        """
        import json  # local to avoid module-level import overhead

        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue

                # Try JSONL first
                if line.startswith("{"):
                    try:
                        obj = json.loads(line)
                        yield {
                            "template": obj.get("template-id", ""),
                            "protocol": obj.get("type", ""),
                            "severity": obj.get("info", {}).get("severity", ""),
                            "target": obj.get("matched-at", ""),
                            "name": obj.get("info", {}).get("name", ""),
                            "description": obj.get("info", {}).get("description", ""),
                        }
                        continue
                    except (json.JSONDecodeError, AttributeError):
                        pass

                # Fall back to bracket-delimited text format:
                # [template] [protocol] [severity] target extra...
                if "[" in line and "]" in line:
                    parts = line.split(" ", 3)
                    if len(parts) >= 4:
                        yield {
                            "template": parts[0].strip("[]"),
                            "protocol": parts[1].strip("[]"),
                            "severity": parts[2].strip("[]"),
                            "target": parts[3].strip(),
                            "name": "",
                            "description": "",
                        }
