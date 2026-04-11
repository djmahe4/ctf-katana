"""Tests for the skill registry (server/registry.py)."""

from pathlib import Path

from server.registry import discover_skills, list_skill_names

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"


class TestRegistry:

    def test_discover_all_skills(self):
        skills = discover_skills(SKILLS_DIR)
        expected = {
            "analysis", "android-analyzer", "binary_exploit", "challenge-gen", 
            "chrome-scraper", "crypto_solver", "ctfd_manage", "ctfd_setup", 
            "ctfd_solve", "ctftime", "exploit_gen", "flagger", "forensics", 
            "fuzzing", "ghactions-exploitation", "iot-analyzer", "kavach_shield", 
            "kavach_wrapper", "merger", "purple-loop-orchestrator", "recon", 
            "research-agent", "research-rag", "research-swarm", 
            "research-youtube-ocr", "reverse", "reverse_engineering", 
            "stego_solver", "superpowers", "vuln-discovery", "web", 
            "web3-analyzer", "web_exploit (DEPRECATED)", "windows-exploitation", 
            "writeup_generator"
        }
        assert expected.issubset(skills.keys())

    def test_skill_has_meta(self):
        skills = discover_skills(SKILLS_DIR)
        for name, skill in skills.items():
            assert skill.meta.name == name
            assert skill.meta.description

    def test_skill_has_run(self):
        """Every skill should have a callable run function."""
        skills = discover_skills(SKILLS_DIR)
        for name, skill in skills.items():
            assert callable(skill.run), f"{name} missing run()"

    def test_skill_has_prompt(self):
        skills = discover_skills(SKILLS_DIR)
        for name, skill in skills.items():
            assert skill.prompt, f"{name} missing prompt.md content"

    def test_list_skill_names(self):
        names = list_skill_names(SKILLS_DIR)
        assert "analysis" in names
        assert "crypto_solver" in names
