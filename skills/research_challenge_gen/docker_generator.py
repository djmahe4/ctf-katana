"""
Docker generation and schema validation for CTF challenge containers.

Phase 3 rules (from spec):
  Step 3.1  Docker image MUST be tagged  ctf-challenge-base:latest
  Step 3.2  Embed vulnerability exactly — no extra attack surface
  Step 3.3  Inject flag via /flag.txt  OR  ENV FLAG=...
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List


REQUIRED_BASE_IMAGE = "ctf-challenge-base:latest"

# Default exposed ports per CTF category (Step 3.2: minimal surface)
_CATEGORY_PORTS: dict = {
    "web":      [5000],
    "pwn":      [1337],
    "web3":     [8545],
    "iot":      [],
    "reverse":  [],
    "crypto":   [],
    "forensics": [],
    "misc":     [],
    "mobile":   [],
}


class FlagInjectionMethod(str, Enum):
    """How the flag is injected into the container (Step 3.3)."""
    FILE = "file"   # RUN echo '...' > /flag.txt
    ENV  = "env"    # ENV FLAG=...


class DockerValidationError(ValueError):
    """Raised when a Dockerfile violates Phase 3 rules."""


@dataclass
class DockerSpec:
    """
    Validated Dockerfile specification for a CTF challenge container.

    Raises DockerValidationError on construction if rules are violated.
    """
    base_image: str
    flag_injection: FlagInjectionMethod
    flag_value: str
    category: str
    ports: List[int] = field(default_factory=list)
    dockerfile: str = ""

    def __post_init__(self) -> None:
        # Rule: base image must be exactly ctf-challenge-base:latest
        if self.base_image != REQUIRED_BASE_IMAGE:
            raise DockerValidationError(
                f"base_image must be '{REQUIRED_BASE_IMAGE}', got '{self.base_image}'"
            )
        # Rule: injection method must be a valid FlagInjectionMethod
        if self.flag_injection not in (FlagInjectionMethod.FILE, FlagInjectionMethod.ENV):
            raise DockerValidationError(
                f"flag_injection must be 'file' or 'env', got '{self.flag_injection}'"
            )


class DockerGenerator:
    """
    Generates and validates Dockerfiles for CTF challenges.
    Enforces Phase 3 containerization rules end-to-end.
    """

    REQUIRED_BASE = REQUIRED_BASE_IMAGE

    # ── Public API ──────────────────────────────────────────────────────────

    def generate(
        self,
        challenge: dict,
        flag: str,
        injection_method: FlagInjectionMethod = FlagInjectionMethod.FILE,
    ) -> DockerSpec:
        """
        Build a validated DockerSpec for a challenge dict.

        Parameters
        ----------
        challenge:
            Challenge data dict (keys: category, name, …).
        flag:
            The flag string to inject (e.g. ``flag{xor_42}``).
        injection_method:
            Whether to inject via /flag.txt or ENV FLAG.

        Returns
        -------
        DockerSpec
            A fully validated specification including rendered Dockerfile content.
        """
        category = challenge.get("category", "misc").lower()
        ports = list(_CATEGORY_PORTS.get(category, []))
        dockerfile = self._build_dockerfile(category, flag, injection_method, ports)
        self.validate(dockerfile)
        return DockerSpec(
            base_image=self.REQUIRED_BASE,
            flag_injection=injection_method,
            flag_value=flag,
            category=category,
            ports=ports,
            dockerfile=dockerfile,
        )

    def validate(self, dockerfile_content: str) -> None:
        """
        Validate a Dockerfile string against Phase 3 rules.

        Raises DockerValidationError on any violation so callers can
        patch or regenerate rather than silently deploying a bad image.
        """
        if not dockerfile_content or not dockerfile_content.strip():
            raise DockerValidationError("Dockerfile content is empty.")

        # Rule 3.1 — FROM must be ctf-challenge-base:latest
        from_match = re.search(
            r"^\s*FROM\s+(\S+)",
            dockerfile_content,
            re.MULTILINE | re.IGNORECASE,
        )
        if not from_match:
            raise DockerValidationError("Dockerfile is missing a FROM instruction.")
        found_image = from_match.group(1).strip()
        if found_image != self.REQUIRED_BASE:
            raise DockerValidationError(
                f"Dockerfile FROM must be '{self.REQUIRED_BASE}', found '{found_image}'."
            )

        # Rule 3.3 — flag injected via /flag.txt or ENV FLAG
        has_flag_file = bool(re.search(r"/flag\.txt", dockerfile_content))
        has_flag_env  = bool(re.search(r"\bENV\s+FLAG\s*=", dockerfile_content))
        if not has_flag_file and not has_flag_env:
            raise DockerValidationError(
                "Dockerfile must inject the flag via '/flag.txt' or 'ENV FLAG=...'."
            )

    def patch_base_image(self, dockerfile_content: str) -> str:
        """
        Replace the FROM line in an existing Dockerfile with the required base image.
        Returns the patched content without modifying flag injection.
        """
        patched = re.sub(
            r"^\s*FROM\s+\S+",
            f"FROM {self.REQUIRED_BASE}",
            dockerfile_content,
            count=1,
            flags=re.MULTILINE | re.IGNORECASE,
        )
        return patched

    # ── Internal helpers ────────────────────────────────────────────────────

    def _build_dockerfile(
        self,
        category: str,
        flag: str,
        injection_method: FlagInjectionMethod,
        ports: List[int],
    ) -> str:
        """Render a minimal, spec-compliant Dockerfile for the given category."""
        lines: List[str] = []

        # Step 3.1 — base image
        lines.append(f"FROM {self.REQUIRED_BASE}")
        lines.append("")
        lines.append("WORKDIR /app")
        lines.append("COPY . /app/")
        lines.append("")

        # Step 3.2 — only the strictly required dependency layer (no extra surface)
        if category == "web":
            lines.append(
                "RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true"
            )
        elif category in ("pwn", "reverse"):
            lines.append(
                "RUN apt-get update -qq && apt-get install -y --no-install-recommends"
                " gcc 2>/dev/null || true"
            )
        elif category == "web3":
            lines.append("RUN npm install 2>/dev/null || true")
        lines.append("")

        # Step 3.3 — flag injection
        if injection_method == FlagInjectionMethod.FILE:
            lines.append(f"RUN echo '{flag}' > /flag.txt && chmod 444 /flag.txt")
        else:
            lines.append(f"ENV FLAG={flag}")
        lines.append("")

        # Expose only the ports needed for this category
        for port in ports:
            lines.append(f"EXPOSE {port}")
        if ports:
            lines.append("")

        # Minimal default entrypoint per category
        if category == "web":
            lines.append('CMD ["python", "app.py"]')
        elif category in ("pwn", "reverse"):
            lines.append('CMD ["./challenge"]')
        elif category == "web3":
            lines.append('CMD ["node", "server.js"]')
        else:
            lines.append('CMD ["/bin/sh"]')

        return "\n".join(lines)
