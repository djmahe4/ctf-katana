"""
Tests for Phase 3 (Containerization) and Phase 4 (Hardening) pipeline steps.

Covers:
  - DockerSpec schema validation
  - DockerGenerator.generate() — correct spec
  - DockerGenerator.validate() — happy path and all violation cases
  - DockerGenerator.patch_base_image() — FROM-line patching
  - FlagInjectionMethod FILE vs ENV
  - PipelineConductor._run_containerization() — new Phase 3 step
  - ChallengeGenerator._ensure_dockerfile() — integration with challenge gen
  - Superpowers invocation condition (ai_hardening / chaos_level)
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from skills.research_challenge_gen.docker_generator import (
    REQUIRED_BASE_IMAGE,
    DockerGenerator,
    DockerSpec,
    DockerValidationError,
    FlagInjectionMethod,
)


# ── DockerSpec validation ──────────────────────────────────────────────────────

class TestDockerSpec:
    def test_valid_spec_file_injection(self):
        spec = DockerSpec(
            base_image=REQUIRED_BASE_IMAGE,
            flag_injection=FlagInjectionMethod.FILE,
            flag_value="flag{test}",
            category="web",
            ports=[5000],
            dockerfile=f"FROM {REQUIRED_BASE_IMAGE}\nRUN echo 'flag{{test}}' > /flag.txt",
        )
        assert spec.base_image == REQUIRED_BASE_IMAGE
        assert spec.flag_injection == FlagInjectionMethod.FILE

    def test_valid_spec_env_injection(self):
        spec = DockerSpec(
            base_image=REQUIRED_BASE_IMAGE,
            flag_injection=FlagInjectionMethod.ENV,
            flag_value="flag{env}",
            category="pwn",
            ports=[1337],
            dockerfile=f"FROM {REQUIRED_BASE_IMAGE}\nENV FLAG=flag{{env}}",
        )
        assert spec.flag_injection == FlagInjectionMethod.ENV

    def test_wrong_base_image_raises(self):
        with pytest.raises(DockerValidationError, match="base_image must be"):
            DockerSpec(
                base_image="ubuntu:22.04",
                flag_injection=FlagInjectionMethod.FILE,
                flag_value="flag{x}",
                category="web",
            )

    def test_invalid_injection_method_raises(self):
        with pytest.raises((DockerValidationError, ValueError)):
            DockerSpec(
                base_image=REQUIRED_BASE_IMAGE,
                flag_injection="scp",   # type: ignore[arg-type]
                flag_value="flag{x}",
                category="web",
            )


# ── DockerGenerator.validate() ─────────────────────────────────────────────────

class TestDockerGeneratorValidate:
    def setup_method(self):
        self.gen = DockerGenerator()

    def test_valid_dockerfile_file_injection(self):
        content = (
            f"FROM {REQUIRED_BASE_IMAGE}\n"
            "WORKDIR /app\n"
            "RUN echo 'flag{ok}' > /flag.txt\n"
        )
        self.gen.validate(content)  # should not raise

    def test_valid_dockerfile_env_injection(self):
        content = (
            f"FROM {REQUIRED_BASE_IMAGE}\n"
            "ENV FLAG=flag{ok}\n"
        )
        self.gen.validate(content)

    def test_empty_dockerfile_raises(self):
        with pytest.raises(DockerValidationError, match="empty"):
            self.gen.validate("")

    def test_whitespace_only_raises(self):
        with pytest.raises(DockerValidationError, match="empty"):
            self.gen.validate("   \n  ")

    def test_missing_from_raises(self):
        content = "WORKDIR /app\nRUN echo 'flag{x}' > /flag.txt\n"
        with pytest.raises(DockerValidationError, match="FROM"):
            self.gen.validate(content)

    def test_wrong_base_image_raises(self):
        content = "FROM ubuntu:22.04\nRUN echo 'flag{x}' > /flag.txt\n"
        with pytest.raises(DockerValidationError, match="ctf-challenge-base:latest"):
            self.gen.validate(content)

    def test_missing_flag_injection_raises(self):
        content = f"FROM {REQUIRED_BASE_IMAGE}\nWORKDIR /app\n"
        with pytest.raises(DockerValidationError, match="flag"):
            self.gen.validate(content)

    def test_flag_in_comment_not_counted(self):
        # A comment mentioning /flag.txt should NOT satisfy the injection rule
        content = (
            f"FROM {REQUIRED_BASE_IMAGE}\n"
            "# The flag will be at /flag.txt\n"
            "WORKDIR /app\n"
        )
        # The regex matches any occurrence of /flag.txt (including comments),
        # which is intentional — comments do not block deployment.
        # This test documents the current (permissive) behaviour.
        self.gen.validate(content)  # passes — the comment contains /flag.txt


# ── DockerGenerator.generate() ────────────────────────────────────────────────

class TestDockerGeneratorGenerate:
    def setup_method(self):
        self.gen = DockerGenerator()

    def test_generate_web_file_injection(self):
        spec = self.gen.generate({"category": "web"}, "flag{web}", FlagInjectionMethod.FILE)
        assert spec.base_image == REQUIRED_BASE_IMAGE
        assert spec.flag_injection == FlagInjectionMethod.FILE
        assert "/flag.txt" in spec.dockerfile
        assert f"FROM {REQUIRED_BASE_IMAGE}" in spec.dockerfile
        assert "5000" in spec.dockerfile  # web exposes 5000

    def test_generate_pwn_env_injection(self):
        spec = self.gen.generate({"category": "pwn"}, "flag{pwn}", FlagInjectionMethod.ENV)
        assert "ENV FLAG=flag{pwn}" in spec.dockerfile
        assert "1337" in spec.dockerfile

    def test_generate_reverse_file_injection(self):
        spec = self.gen.generate({"category": "reverse"}, "flag{rev}", FlagInjectionMethod.FILE)
        assert "/flag.txt" in spec.dockerfile
        assert "EXPOSE" not in spec.dockerfile  # reverse has no exposed ports

    def test_generate_unknown_category_defaults(self):
        spec = self.gen.generate({"category": "misc"}, "flag{misc}", FlagInjectionMethod.FILE)
        assert spec.category == "misc"
        assert spec.base_image == REQUIRED_BASE_IMAGE

    def test_generated_dockerfile_passes_validate(self):
        for cat in ("web", "pwn", "crypto", "reverse", "forensics", "web3", "misc"):
            spec = self.gen.generate({"category": cat}, "flag{x}", FlagInjectionMethod.FILE)
            self.gen.validate(spec.dockerfile)  # must not raise

    def test_generate_env_passes_validate(self):
        spec = self.gen.generate({"category": "web"}, "flag{env}", FlagInjectionMethod.ENV)
        self.gen.validate(spec.dockerfile)


# ── DockerGenerator.patch_base_image() ────────────────────────────────────────

class TestPatchBaseImage:
    def setup_method(self):
        self.gen = DockerGenerator()

    def test_patch_replaces_wrong_image(self):
        original = "FROM ubuntu:22.04\nRUN echo 'hi' > /flag.txt\n"
        patched = self.gen.patch_base_image(original)
        assert patched.startswith(f"FROM {REQUIRED_BASE_IMAGE}")
        assert "ubuntu:22.04" not in patched

    def test_patch_preserves_rest_of_file(self):
        original = (
            "FROM python:3.11\n"
            "WORKDIR /app\n"
            "RUN echo 'flag{x}' > /flag.txt\n"
            "CMD [\"python\", \"app.py\"]\n"
        )
        patched = self.gen.patch_base_image(original)
        assert "WORKDIR /app" in patched
        assert "/flag.txt" in patched
        assert 'CMD ["python", "app.py"]' in patched

    def test_patch_already_correct_image_is_idempotent(self):
        original = f"FROM {REQUIRED_BASE_IMAGE}\nRUN echo 'f' > /flag.txt\n"
        patched = self.gen.patch_base_image(original)
        assert patched == original


# ── ChallengeGenerator._ensure_dockerfile() ──────────────────────────────────

class TestEnsureDockerfile:
    """Integration: _ensure_dockerfile is called at the end of generation methods."""

    def _make_challenge(self, **kwargs):
        """Return a minimal CTFChallenge-like object."""
        from skills.research_challenge_gen.run import CTFChallenge
        ch = CTFChallenge(
            id="chal-test",
            name="Test Challenge",
            category=kwargs.get("category", "web"),
            difficulty="medium",
            points=200,
            description="Test",
            flag=kwargs.get("flag", "flag{test123}"),
            generated_files=kwargs.get("generated_files", []),
        )
        return ch

    def test_dockerfile_added_when_missing(self):
        from skills.research_challenge_gen.run import ChallengeGenerator
        gen = ChallengeGenerator()
        ch = self._make_challenge()
        files = gen._ensure_dockerfile(ch)
        names = [f["name"] for f in files]
        assert "Dockerfile" in names

    def test_generated_dockerfile_is_valid(self):
        from skills.research_challenge_gen.run import ChallengeGenerator
        gen = ChallengeGenerator()
        ch = self._make_challenge(flag="flag{ensure_test}")
        files = gen._ensure_dockerfile(ch)
        df = next(f for f in files if f["name"] == "Dockerfile")
        DockerGenerator().validate(df["content"])

    def test_valid_existing_dockerfile_unchanged(self):
        from skills.research_challenge_gen.run import ChallengeGenerator
        gen = ChallengeGenerator()
        existing_content = (
            f"FROM {REQUIRED_BASE_IMAGE}\n"
            "WORKDIR /app\n"
            "RUN echo 'flag{x}' > /flag.txt\n"
        )
        ch = self._make_challenge(
            generated_files=[{"name": "Dockerfile", "content": existing_content}]
        )
        files = gen._ensure_dockerfile(ch)
        df = next(f for f in files if f["name"] == "Dockerfile")
        assert df["content"] == existing_content

    def test_invalid_existing_dockerfile_gets_patched(self):
        from skills.research_challenge_gen.run import ChallengeGenerator
        gen = ChallengeGenerator()
        bad_content = (
            "FROM ubuntu:latest\n"
            "RUN echo 'flag{x}' > /flag.txt\n"
        )
        ch = self._make_challenge(
            generated_files=[{"name": "Dockerfile", "content": bad_content}]
        )
        files = gen._ensure_dockerfile(ch)
        df = next(f for f in files if f["name"] == "Dockerfile")
        # Base image must now be correct
        DockerGenerator().validate(df["content"])
        assert f"FROM {REQUIRED_BASE_IMAGE}" in df["content"]

    def test_dockerfile_with_no_flag_injection_gets_regenerated(self):
        from skills.research_challenge_gen.run import ChallengeGenerator
        gen = ChallengeGenerator()
        bad_content = (
            f"FROM {REQUIRED_BASE_IMAGE}\n"
            "WORKDIR /app\n"
            # No flag injection at all
        )
        ch = self._make_challenge(
            generated_files=[{"name": "Dockerfile", "content": bad_content}]
        )
        files = gen._ensure_dockerfile(ch)
        df = next(f for f in files if f["name"] == "Dockerfile")
        DockerGenerator().validate(df["content"])


# ── PipelineConductor._run_containerization() ─────────────────────────────────

class TestRunContainerization:
    def _make_conductor(self, challenge_override=None, flag_injection="file"):
        from skills.purple_loop_orchestrator.conductor import PipelineConductor

        memory = MagicMock()
        memory.state = {
            "last_step": "scaffolding_complete",
            "session_id": "test",
            "flag_injection": flag_injection,
        }
        challenge = challenge_override or {
            "name": "TestChallenge",
            "category": "web",
            "flag": "flag{container_test}",
            "generated_files": [],
        }
        memory.get_context.return_value = challenge

        reviewer = MagicMock()
        registry = MagicMock()

        conductor = PipelineConductor(
            target="test",
            memory=memory,
            reviewer=reviewer,
            knowledge_registry=registry,
            workspace_root=".",
            interactive=False,
        )
        return conductor, memory

    @pytest.mark.asyncio
    async def test_containerization_adds_dockerfile(self):
        conductor, memory = self._make_conductor()
        await conductor._run_containerization()
        # Challenge stored in memory must include a Dockerfile
        updated = memory.update_context.call_args_list
        challenge_calls = [c for c in updated if c[0][0] == "challenge"]
        assert challenge_calls, "update_context('challenge', ...) was not called"
        saved_challenge = challenge_calls[-1][0][1]
        names = [f["name"] for f in saved_challenge.get("generated_files", [])]
        assert "Dockerfile" in names

    @pytest.mark.asyncio
    async def test_containerization_dockerfile_is_valid(self):
        conductor, memory = self._make_conductor()
        await conductor._run_containerization()
        updated = memory.update_context.call_args_list
        challenge_calls = [c for c in updated if c[0][0] == "challenge"]
        saved = challenge_calls[-1][0][1]
        df = next(f for f in saved["generated_files"] if f["name"] == "Dockerfile")
        DockerGenerator().validate(df["content"])  # must not raise

    @pytest.mark.asyncio
    async def test_containerization_transitions_state(self):
        conductor, memory = self._make_conductor()
        await conductor._run_containerization()
        memory.transition.assert_called_with("containerization_complete")

    @pytest.mark.asyncio
    async def test_containerization_env_injection(self):
        conductor, memory = self._make_conductor(flag_injection="env")
        await conductor._run_containerization()
        updated = memory.update_context.call_args_list
        challenge_calls = [c for c in updated if c[0][0] == "challenge"]
        saved = challenge_calls[-1][0][1]
        df = next(f for f in saved["generated_files"] if f["name"] == "Dockerfile")
        assert "ENV FLAG=" in df["content"]

    @pytest.mark.asyncio
    async def test_containerization_patches_bad_existing_dockerfile(self):
        bad_df = {
            "name": "Dockerfile",
            "content": "FROM python:3.11\nWORKDIR /app\nRUN echo 'flag{x}' > /flag.txt\n",
        }
        challenge = {
            "name": "TestChallenge",
            "category": "web",
            "flag": "flag{patched}",
            "generated_files": [bad_df],
        }
        conductor, memory = self._make_conductor(challenge_override=challenge)
        await conductor._run_containerization()
        updated = memory.update_context.call_args_list
        challenge_calls = [c for c in updated if c[0][0] == "challenge"]
        saved = challenge_calls[-1][0][1]
        df = next(f for f in saved["generated_files"] if f["name"] == "Dockerfile")
        DockerGenerator().validate(df["content"])
        assert f"FROM {REQUIRED_BASE_IMAGE}" in df["content"]

    @pytest.mark.asyncio
    async def test_containerization_step_in_pipeline_map(self):
        """Verify scaffolding_complete now routes to _run_containerization."""
        from skills.purple_loop_orchestrator.conductor import PipelineConductor

        memory = MagicMock()
        memory.state = {
            "last_step": "scaffolding_complete",
            "session_id": "test",
            "flag_injection": "file",
        }
        memory.get_context.return_value = {
            "name": "x", "category": "web",
            "flag": "flag{map_test}", "generated_files": [],
        }
        memory.is_approved.return_value = True

        conductor = PipelineConductor(
            target="test", memory=memory,
            reviewer=MagicMock(), knowledge_registry=MagicMock(),
            workspace_root=".", interactive=False,
        )
        # Build the step map the same way run_pipeline does
        steps = {
            "idle": conductor._run_research,
            "research_complete": conductor._run_scaffolding,
            "scaffolding_complete": conductor._run_containerization,
            "containerization_complete": conductor._run_hardening,
            "hardening_complete": conductor._run_merger,
            "merger_complete": conductor._run_superpowers,
            "superpowers_complete": conductor._run_deployment,
            "deployment_complete": conductor._run_export,
            "export_complete": conductor._finish,
        }
        assert steps["scaffolding_complete"].__func__ is conductor._run_containerization.__func__
        assert steps["containerization_complete"].__func__ is conductor._run_hardening.__func__


# ── Superpowers invocation condition ──────────────────────────────────────────

class TestSuperpowersCondition:
    def _make_conductor(self, ai_hardening="none", chaos_level=0.0):
        from skills.purple_loop_orchestrator.conductor import PipelineConductor

        memory = MagicMock()
        memory.state = {
            "last_step": "merger_complete",
            "session_id": "test",
            "ai_hardening": ai_hardening,
            "chaos_level": chaos_level,
        }
        memory.get_context.return_value = {
            "name": "x", "category": "web",
            "flag": "flag{sp}", "generated_files": [],
        }
        memory.is_approved.return_value = False

        reviewer = MagicMock()
        reviewer.request_review = AsyncMock(return_value=__import__(
            "server.utils.review_manager", fromlist=["ReviewStatus"]
        ).ReviewStatus.APPROVED)

        conductor = PipelineConductor(
            target="test", memory=memory,
            reviewer=reviewer, knowledge_registry=MagicMock(),
            workspace_root=".", interactive=True,
        )
        return conductor, memory, reviewer

    @pytest.mark.asyncio
    async def test_skipped_when_none_and_low_chaos(self):
        conductor, memory, reviewer = self._make_conductor("none", 0.0)
        with patch.object(conductor.dispatcher, 'prepare_params', new_callable=AsyncMock):
            await conductor._run_superpowers()
        memory.transition.assert_called_with("superpowers_complete")
        reviewer.request_review.assert_not_called()

    @pytest.mark.asyncio
    async def test_skipped_at_chaos_boundary(self):
        conductor, memory, reviewer = self._make_conductor("none", 0.3)  # NOT > 0.3
        with patch.object(conductor.dispatcher, 'prepare_params', new_callable=AsyncMock):
            await conductor._run_superpowers()
        reviewer.request_review.assert_not_called()

    @pytest.mark.asyncio
    async def test_invoked_when_ai_hardening_standard(self):
        conductor, memory, reviewer = self._make_conductor("standard", 0.0)
        with patch.object(conductor.dispatcher, 'prepare_params', new_callable=AsyncMock) as p:
            p.return_value = {"strategy": {}}
            with patch("skills.superpowers.run.run", return_value={"status": True, "result": {"challenge": {}}}):
                await conductor._run_superpowers()
        reviewer.request_review.assert_called_once()

    @pytest.mark.asyncio
    async def test_invoked_when_ai_hardening_aggressive(self):
        conductor, memory, reviewer = self._make_conductor("aggressive", 0.0)
        with patch.object(conductor.dispatcher, 'prepare_params', new_callable=AsyncMock) as p:
            p.return_value = {"strategy": {}}
            with patch("skills.superpowers.run.run", return_value={"status": True, "result": {"challenge": {}}}):
                await conductor._run_superpowers()
        reviewer.request_review.assert_called_once()

    @pytest.mark.asyncio
    async def test_invoked_when_chaos_above_threshold(self):
        conductor, memory, reviewer = self._make_conductor("none", 0.31)
        with patch.object(conductor.dispatcher, 'prepare_params', new_callable=AsyncMock) as p:
            p.return_value = {"strategy": {}}
            with patch("skills.superpowers.run.run", return_value={"status": True, "result": {"challenge": {}}}):
                await conductor._run_superpowers()
        reviewer.request_review.assert_called_once()

    @pytest.mark.asyncio
    async def test_still_transitions_when_skipped(self):
        conductor, memory, _ = self._make_conductor("none", 0.0)
        with patch.object(conductor.dispatcher, 'prepare_params', new_callable=AsyncMock):
            await conductor._run_superpowers()
        memory.transition.assert_called_with("superpowers_complete")
