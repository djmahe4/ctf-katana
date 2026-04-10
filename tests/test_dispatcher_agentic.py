import pytest
import json
from unittest.mock import AsyncMock, patch
from server.utils.agentic_dispatcher import AgenticSkillDispatcher

@pytest.fixture
def dispatcher():
    return AgenticSkillDispatcher(workspace_root=".")

@pytest.mark.asyncio
async def test_prepare_params_merger(dispatcher):
    """Verify dispatcher correctly plans a merger layout."""
    context = {
        "challenge_history": [
            {"name": "web1", "category": "web", "generated_files": [{"name": "index.html"}]}
        ],
        "session_id": "test_session"
    }

    mock_layout = {
        "mergeable": True,
        "services": [
            {"name": "service_1", "external_port": 9000, "internal_port": 80}
        ]
    }

    # Patch the internal architectural check directly for prepare_params test
    with patch.object(dispatcher, '_plan_merger_layout', new_callable=AsyncMock) as mock_plan:
        mock_plan.return_value = mock_layout
        with patch.object(dispatcher, '_read_skill_prompt', new_callable=AsyncMock) as mock_prompt:
            mock_prompt.return_value = "system prompt"
            
            params = await dispatcher.prepare_params("merger", context)
            
            assert params["target_session"] == "test_session"
            assert params["layout_plan"] == mock_layout
            assert len(params["selected_components"]) == 1

@pytest.mark.asyncio
async def test_prepare_params_superpowers(dispatcher):
    """Verify dispatcher correctly plans adversarial strategy."""
    context = {
        "challenge": {"name": "Test", "generated_files": [{"name": "app.py"}]},
        "chaos_level": 0.8
    }

    mock_strategy = {
        "name": "Loki-Mock",
        "injections": [{"file": "app.py", "type": "trap", "content": "poison"}]
    }

    with patch.object(dispatcher, '_plan_adversarial_strategy', new_callable=AsyncMock) as mock_plan:
        mock_plan.return_value = mock_strategy
        with patch.object(dispatcher, '_read_skill_prompt', new_callable=AsyncMock) as mock_prompt:
            mock_prompt.return_value = "adversarial prompt"
            
            params = await dispatcher.prepare_params("superpowers", context)
            
            assert params["chaos_level"] == 0.8
            assert params["strategy"] == mock_strategy
            assert params["challenge"]["name"] == "Test"

@pytest.mark.asyncio
async def test_ollama_failure_fallback(dispatcher):
    """Verify dispatcher handles Ollama HTTP errors gracefully."""
    # Patch the lower level post call to verify fallback logic
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        # Simulate a context manager and failure
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("Ollama connection refused")
        # Since dispatcher uses 'async with httpx.AsyncClient(...) as client:',
        # we need to patch the constructor to return our mock_client
        with patch("httpx.AsyncClient", return_value=mock_client):
            strategy = await dispatcher._plan_adversarial_strategy("prompt", "files", 0.5)
            
            assert strategy["status"] is False
            assert "injections" in strategy
            assert len(strategy["injections"]) == 0
