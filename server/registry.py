"""Skill registry – discovers and loads skills from ``skills/`` directory.

Each skill is a sub-directory containing:

* ``skill.yaml`` – metadata (name, description, inputs, tools, category)
* ``prompt.md``  – LLM reasoning instructions
* ``run.py``     – execution logic with a ``run(inputs) -> dict`` entry-point
"""

from __future__ import annotations

import importlib.util
import types
import sys
import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml
logger = logging.getLogger(__name__)


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
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _load_module(path: Path, module_name: str) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None:
        raise ImportError(f"Cannot create module spec for {path}")
    if spec.loader is None:
        raise ImportError(f"Module spec for {path} has no loader")
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

    # Add project root to sys.path to allow skills to import from the root package
    root_dir = str(Path(__file__).resolve().parent.parent)
    if root_dir not in sys.path:
        sys.path.insert(0, root_dir)

    skills: Dict[str, Skill] = {}

    if not skills_dir.is_dir():
        return skills

    # Use glob to find all skill.yaml files recursively
    for yaml_path in sorted(skills_dir.glob("**/skill.yaml")):
        child = yaml_path.parent
        
        # Skill identity based on relative path to skills_dir
        try:
            skill_id = str(child.relative_to(skills_dir)).replace(os.sep, ".")
        except ValueError:
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

        # Prompt
        prompt_path = child / "prompt.md"
        prompt_content = ""
        if prompt_path.exists():
            prompt_content = prompt_path.read_text(encoding="utf-8")
        
        # Loader (run.py)
        run_py = child / "run.py"
        if not run_py.exists():
            continue
            
        try:
            # Load module using unique name based on path
            module_name = f"skills.{skill_id}.run"
            spec = importlib.util.spec_from_file_location(module_name, run_py)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                # Keep track of the module in sys.modules to avoid double-loading or import issues
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
                run_fn = getattr(module, "run", None)
                
                if run_fn:
                    skills[meta.name] = Skill(
                        meta=meta,
                        prompt=prompt_content,
                        run=run_fn,
                        directory=child
                    )
        except Exception as e:
            logger.error(f"Failed to load skill at {child}: {e}")
            continue

    return skills


def list_skill_names(skills_dir: Optional[Path] = None) -> List[str]:
    """Return a sorted list of discovered skill names."""
    return sorted(discover_skills(skills_dir).keys())
