import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from skills.purple_loop_orchestrator.conductor import PipelineConductor
from server.utils.review_manager import ReviewStatus

@pytest.fixture
def mock_deps():
    memory = MagicMock()
    # chaos_level > 0.3 so superpowers is invoked; ai_hardening explicit
    memory.state = {
        "last_step": "hardening_complete",
        "session_id": "test_session",
        "ai_hardening": "standard",
        "chaos_level": 0.5,
    }
    memory.get_context.return_value = {"name": "test_challenge", "category": "web"}
    memory.is_approved.return_value = False
    
    reviewer = MagicMock()
    reviewer.request_review = AsyncMock(return_value=ReviewStatus.APPROVED)
    
    registry = MagicMock()
    
    return memory, reviewer, registry

@pytest.mark.asyncio
async def test_conductor_merger_to_superpowers_transition(mock_deps):
    """Verify conductor transition: hardening_complete -> merger_complete -> superpowers_complete."""
    memory, reviewer, registry = mock_deps
    
    conductor = PipelineConductor(
        target="CVE-2024-TEST",
        memory=memory,
        reviewer=reviewer,
        knowledge_registry=registry,
        workspace_root=".",
        interactive=True
    )

    # Mock Skill Execution and Dispatcher
    with patch.object(conductor.dispatcher, 'prepare_params', new_callable=AsyncMock) as mock_prep:
        mock_prep.return_value = {"status": "mocked_params"}
        with patch("skills.merger.run.run") as mock_run_merger:
            mock_run_merger.return_value = {"status": True, "merged_challenge": {"name": "merged"}}
            with patch("skills.superpowers.run.run") as mock_run_superpowers:
                mock_run_superpowers.return_value = {"status": True, "challenge": {"name": "ai_hard"}}
                
                # We need to simulate the loop or call handlers directly for surgical testing
                # Let's test _run_merger
                await conductor._run_merger()
                
                # Verify transitions
                memory.transition.assert_called_with("merger_complete")
                reviewer.request_review.assert_called() # Merger layout review
                
                # Test _run_superpowers with ai_hardening=standard (satisfies invocation condition)
                memory.state["last_step"] = "merger_complete"
                await conductor._run_superpowers()
                
                memory.transition.assert_called_with("superpowers_complete")
                # Should have requested review for adversarial strategy
                assert reviewer.request_review.call_count >= 2

@pytest.mark.asyncio
async def test_conductor_superpowers_skipped_when_condition_not_met(mock_deps):
    """Verify superpowers is skipped when ai_hardening=none and chaos_level<=0.3."""
    memory, reviewer, registry = mock_deps
    # Override to NOT meet invocation condition
    memory.state["ai_hardening"] = "none"
    memory.state["chaos_level"] = 0.0

    conductor = PipelineConductor(
        target="CVE-2024-TEST",
        memory=memory,
        reviewer=reviewer,
        knowledge_registry=registry,
        workspace_root=".",
        interactive=True,
    )

    with patch.object(conductor.dispatcher, 'prepare_params', new_callable=AsyncMock):
        await conductor._run_superpowers()

    # Must still transition so the pipeline can continue
    memory.transition.assert_called_with("superpowers_complete")
    # No review should have been requested (skipped entirely)
    reviewer.request_review.assert_not_called()

@pytest.mark.asyncio
async def test_conductor_superpowers_invoked_by_chaos_level(mock_deps):
    """Verify superpowers runs when chaos_level > 0.3 even if ai_hardening=none."""
    memory, reviewer, registry = mock_deps
    memory.state["ai_hardening"] = "none"
    memory.state["chaos_level"] = 0.5  # > 0.3 → invoke

    conductor = PipelineConductor(
        target="CVE-2024-TEST",
        memory=memory,
        reviewer=reviewer,
        knowledge_registry=registry,
        workspace_root=".",
        interactive=True,
    )

    with patch.object(conductor.dispatcher, 'prepare_params', new_callable=AsyncMock) as mock_prep:
        mock_prep.return_value = {"strategy": {"name": "chaos-run"}}
        with patch("skills.superpowers.run.run") as mock_sp:
            mock_sp.return_value = {"status": True, "result": {"challenge": {}}}
            await conductor._run_superpowers()

    reviewer.request_review.assert_called_once()  # adversarial strategy review
    memory.transition.assert_called_with("superpowers_complete")

@pytest.mark.asyncio
async def test_conductor_hitl_rejection(mock_deps):
    """Verify that rejecting a layout/strategy pauses or skips the phase."""
    memory, reviewer, registry = mock_deps
    reviewer.request_review.return_value = ReviewStatus.REJECTED
    
    conductor = PipelineConductor(
        target="CVE-2024-TEST",
        memory=memory,
        reviewer=reviewer,
        knowledge_registry=registry,
        workspace_root=".",
        interactive=True
    )

    with patch.object(conductor.dispatcher, 'prepare_params', new_callable=AsyncMock) as mock_prep:
        mock_prep.return_value = {"strategy": {"name": "Rejected"}}
        
        # Test superpowers rejection (ai_hardening=standard meets invocation condition)
        await conductor._run_superpowers()
        
        # Should transition to complete but log bypass/rejection (current logic transitions anyway or logs)
        # Looking at conductor.py: if rejected, it transitions to complete but doesn't apply results.
        memory.transition.assert_called_with("superpowers_complete")
        # Ensure result was NOT updated in context if rejected (assuming update_context is called on success)
        # Note: In real logic, it returns early.
