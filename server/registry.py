"""Skill registry – discovers and loads skills from ``skills/`` directory.

Each skill is a sub-directory containing:

* ``skill.yaml`` – metadata (name, description, inputs, tools, category)
* ``prompt.md``  – LLM reasoning instructions
* ``run.py``     – execution logic with a ``run(inputs) -> dict`` entry-point
"""

from __future__ import annotations

import importlib.util
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml


@dataclass
class SkillMeta:
    """Parsed metadata from a ``skill.yaml`` file."""

    name: str
    description: str = ""
    inputs: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    category: str = "misc"
    agent: bool = False
    enabled: bool = True


@dataclass
class Skill:
    """A fully-loaded skill: metadata + prompt + run function."""

    meta: SkillMeta
    prompt: str = ""
    run: Optional[Callable[..., Any]] = None
    directory: Optional[Path] = None


def _load_yaml(path: Path) -> dict:
    with open(path, "r") as fh:
        return yaml.safe_load(fh) or {}


def _load_module(path: Path, module_name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def discover_skills(skills_dir: Optional[Path] = None) -> Dict[str, Skill]:
    """Scan *skills_dir* and return a mapping of ``name → Skill``.

    Parameters
    ----------
    skills_dir:
        Directory containing skill sub-directories.  Defaults to the
        ``skills/`` directory in the repository root.
    """
    if skills_dir is None:
        skills_dir = Path(__file__).resolve().parent.parent / "skills"

    skills: Dict[str, Skill] = {}

    if not skills_dir.is_dir():
        return skills

    for child in sorted(skills_dir.iterdir()):
        if not child.is_dir():
            continue
        yaml_path = child / "skill.yaml"
        if not yaml_path.exists():
            continue

        raw = _load_yaml(yaml_path)
        meta = SkillMeta(
            name=raw.get("name", child.name),
            description=raw.get("description", ""),
            inputs=raw.get("inputs", []),
            tools=raw.get("tools", []),
            category=raw.get("category", "misc"),
            agent=raw.get("agent", False),
        )

        # Load prompt
        prompt_path = child / "prompt.md"
        prompt = prompt_path.read_text() if prompt_path.exists() else ""

        # Load run function
        run_path = child / "run.py"
        run_fn = None
        if run_path.exists():
            mod = _load_module(run_path, f"skill_{meta.name}")
            run_fn = getattr(mod, "run", None)

        skills[meta.name] = Skill(
            meta=meta,
            prompt=prompt,
            run=run_fn,
            directory=child,
        )

    return skills


def list_skill_names(skills_dir: Optional[Path] = None) -> List[str]:
    """Return a sorted list of discovered skill names."""
    return sorted(discover_skills(skills_dir).keys())
