"""
Tests for Phase 3: Research Agent & RAG Knowledge Base

Tests research agent orchestration, swarm coordination,
vulnerability discovery, and challenge generation.
"""

import os
import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

import pytest

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


# =============================================================================
# Knowledge Base Tests
# =============================================================================

class TestKnowledgeBase:
    """Test RAG knowledge base functionality."""
    
    def test_document_creation(self):
        """Test Document dataclass creation."""
        from skills.research.knowledge_base import Document
        
        doc = Document(
            id="test-001",
            content="This is test content",
            source="test",
            source_type="manual",
            title="Test Document",
        )
        
        assert doc.id == "test-001"
        assert doc.title == "Test Document"
        assert doc.content == "This is test content"
        assert doc.source == "test"
        assert doc.source_type == "manual"
    
    def test_search_result_creation(self):
        """Test SearchResult dataclass creation."""
        from skills.research.knowledge_base import SearchResult
        
        result = SearchResult(
            document_id="test-001",
            content="Content here",
            source="test",
            source_type="manual",
            title="Test Result",
            url="",
            tags=[],
            score=0.15,
            relevance=0.85,
        )
        
        assert result.document_id == "test-001"
        assert result.relevance == 0.85
    
    def test_repo_config_creation(self):
        """Test RepoConfig dataclass creation."""
        from skills.research.knowledge_base import RepoConfig
        
        config = RepoConfig(
            url="https://github.com/test/repo",
            name="test-repo",
            include_patterns=["*.py", "*.md"],
            priority=5,
            tags=["security", "python"],
        )
        
        assert config.name == "test-repo"
        assert config.url == "https://github.com/test/repo"
        assert "*.py" in config.include_patterns
        assert config.priority == 5
    
    def test_local_embeddings(self):
        """Test local embedding generation."""
        from skills.research.knowledge_base import LocalEmbeddings
        import numpy as np
        
        embeddings = LocalEmbeddings()
        
        texts = ["Hello world", "Security vulnerability"]
        vectors = embeddings.embed(texts)
        
        assert len(vectors) == 2
        assert vectors.shape[1] == 384  # MiniLM dimension
        assert isinstance(vectors, np.ndarray)
    
    def test_local_embeddings_single(self):
        """Test single text embedding."""
        from skills.research.knowledge_base import LocalEmbeddings
        import numpy as np
        
        embeddings = LocalEmbeddings()
        
        vector = embeddings.embed("Test text")
        
        assert vector.shape[1] == 384
        assert isinstance(vector, np.ndarray)
    
    @patch('skills.research.knowledge_base.chromadb')
    def test_knowledge_base_init(self, mock_chromadb):
        """Test KnowledgeBase initialization."""
        from skills.research.knowledge_base import KnowledgeBase
        
        mock_client = Mock()
        mock_collection = Mock()
        mock_chromadb.PersistentClient.return_value = mock_client
        mock_client.get_or_create_collection.return_value = mock_collection
        
        kb = KnowledgeBase()
        
        mock_chromadb.PersistentClient.assert_called_once()
        mock_client.get_or_create_collection.assert_called_once()
    
    @patch('skills.research.knowledge_base.chromadb')
    def test_knowledge_base_add_document(self, mock_chromadb):
        """Test adding document to knowledge base."""
        from skills.research.knowledge_base import KnowledgeBase
        
        mock_client = Mock()
        mock_collection = Mock()
        mock_collection.get.return_value = {'ids': []}
        mock_chromadb.PersistentClient.return_value = mock_client
        mock_client.get_or_create_collection.return_value = mock_collection
        
        kb = KnowledgeBase()
        
        doc_id = kb.add_document(
            content="Test content for embedding",
            source="test",
            source_type="manual",
            title="Test Document",
        )
        
        assert doc_id is not None
        mock_collection.add.assert_called()
    
    @patch('skills.research.knowledge_base.chromadb')
    def test_knowledge_base_search(self, mock_chromadb):
        """Test searching knowledge base."""
        from skills.research.knowledge_base import KnowledgeBase
        
        mock_client = Mock()
        mock_collection = Mock()
        mock_chromadb.PersistentClient.return_value = mock_client
        mock_client.get_or_create_collection.return_value = mock_collection
        
        # Mock search results
        mock_collection.query.return_value = {
            'ids': [['doc-001_0']],
            'documents': [['Test content']],
            'metadatas': [[{
                'document_id': 'doc-001',
                'title': 'Test', 
                'source': 'test', 
                'source_type': 'manual', 
                'url': '', 
                'tags': '[]'
            }]],
            'distances': [[0.2]],
        }
        
        kb = KnowledgeBase()
        results = kb.search("test query", limit=5)
        
        assert len(results) == 1
        assert results[0].document_id == 'doc-001'
        assert results[0].relevance == pytest.approx(0.8, rel=0.1)  # 1 - distance


# =============================================================================
# Research Agent Tests
# =============================================================================

class TestResearchAgent:
    """Test research agent orchestration."""
    
    def test_research_mode_enum(self):
        """Test ResearchMode enumeration."""
        from skills.research.agent.run import ResearchMode
        
        assert ResearchMode.RESEARCH.value == "research"
        assert ResearchMode.HUNT.value == "hunt"
        assert ResearchMode.VALIDATE.value == "validate"
        assert ResearchMode.GENERATE.value == "generate"
        assert ResearchMode.FULL_CYCLE.value == "full_cycle"
    
    def test_research_depth_enum(self):
        """Test ResearchDepth enumeration."""
        from skills.research.agent.run import ResearchDepth
        
        assert ResearchDepth.QUICK.value == "quick"
        assert ResearchDepth.MEDIUM.value == "medium"
        assert ResearchDepth.DEEP.value == "deep"
    
    def test_finding_dataclass(self):
        """Test Finding dataclass creation."""
        from skills.research.agent.run import Finding
        
        finding = Finding(
            id="FINDING-001",
            title="SQL Injection",
            severity="HIGH",
            confidence=0.9,
            vuln_type="CWE-89",
            description="SQL injection in login",
        )
        
        assert finding.id == "FINDING-001"
        assert finding.severity == "HIGH"
        assert finding.confidence == 0.9
    
    def test_research_result_dataclass(self):
        """Test ResearchResult dataclass creation."""
        from skills.research.agent.run import ResearchResult
        
        result = ResearchResult(
            status="success",
            mode="research",
            topic="SQL injection",
            target=None,
        )
        
        assert result.status == "success"
        assert result.mode == "research"
    
    @patch('skills.research.agent.run.KnowledgeBase')
    def test_research_agent_init(self, mock_kb):
        """Test ResearchAgent initialization."""
        from skills.research.agent.run import ResearchAgent
        
        agent = ResearchAgent()
        
        assert agent.ollama_model == "mistral-nemo"
        assert "localhost:11434" in agent.ollama_host
        mock_kb.assert_called_once()
    
    @patch('skills.research.agent.run.KnowledgeBase')
    @patch('requests.post')
    def test_research_agent_research(self, mock_requests, mock_kb):
        """Test research mode."""
        from skills.research.agent.run import ResearchAgent, ResearchDepth
        
        # Mock KB search
        mock_kb_instance = Mock()
        mock_kb_instance.search.return_value = []
        mock_kb.return_value = mock_kb_instance
        
        # Mock LLM response
        mock_response = Mock()
        mock_response.json.return_value = {
            "message": {"content": "Research findings here"}
        }
        mock_response.raise_for_status = Mock()
        mock_requests.return_value = mock_response
        
        agent = ResearchAgent()
        result = agent.research("SQL injection", ResearchDepth.QUICK)
        
        assert result.status == "success"
        assert result.mode == "research"
        assert result.topic == "SQL injection"
    
    def test_run_function_missing_topic(self):
        """Test run() with missing topic."""
        from skills.research.agent.run import run
        
        result = run({'mode': 'research'})
        
        assert result['status'] == 'error'
        assert 'topic' in result['message'].lower()
    
    def test_run_function_invalid_mode(self):
        """Test run() with invalid mode."""
        from skills.research.agent.run import run
        
        with patch('skills.research.agent.run.KnowledgeBase'):
            result = run({'mode': 'invalid_mode', 'topic': 'test'})
        
        assert result['status'] == 'error'
        assert 'valid_modes' in result


# =============================================================================
# Research Swarm Tests
# =============================================================================

class TestResearchSwarm:
    """Test multi-agent swarm functionality."""
    
    def test_swarm_type_enum(self):
        """Test SwarmType enumeration."""
        from skills.research.swarm.run import SwarmType
        
        assert SwarmType.RECON.value == "recon"
        assert SwarmType.ANALYSIS.value == "analysis"
        assert SwarmType.EXPLOIT.value == "exploit"
        assert SwarmType.BALANCED.value == "balanced"
        assert SwarmType.FULL.value == "full"
    
    def test_agent_type_enum(self):
        """Test AgentType enumeration."""
        from skills.research.swarm.run import AgentType
        
        assert AgentType.URL_SCOUT.value == "url_scout"
        assert AgentType.CODE_REVIEWER.value == "code_reviewer"
        assert AgentType.PAYLOAD_CRAFTER.value == "payload_crafter"
    
    def test_agent_task_dataclass(self):
        """Test AgentTask dataclass."""
        from skills.research.swarm.run import AgentTask
        
        task = AgentTask(
            agent_type="code_reviewer",
            task="Review for vulnerabilities",
            timeout=60,
        )
        
        assert task.agent_type == "code_reviewer"
        assert task.timeout == 60
    
    def test_agent_result_dataclass(self):
        """Test AgentResult dataclass."""
        from skills.research.swarm.run import AgentResult
        
        result = AgentResult(
            agent_type="url_scout",
            status="complete",
            confidence=0.8,
            duration=30.5,
        )
        
        assert result.status == "complete"
        assert result.confidence == 0.8
    
    def test_swarm_composition(self):
        """Test swarm composition mapping."""
        from skills.research.swarm.run import SwarmAgent, SwarmType, AgentType
        
        balanced_agents = SwarmAgent.SWARM_COMPOSITION[SwarmType.BALANCED]
        
        assert len(balanced_agents) == 5
        assert AgentType.URL_SCOUT in balanced_agents
        assert AgentType.CODE_REVIEWER in balanced_agents
    
    @patch('skills.research.swarm.run.KnowledgeBase')
    def test_research_swarm_init(self, mock_kb):
        """Test ResearchSwarm initialization."""
        from skills.research.swarm.run import ResearchSwarm
        
        swarm = ResearchSwarm()
        
        assert swarm.ollama_model == "mistral-nemo"
        mock_kb.assert_called_once()
    
    def test_run_function_missing_topic(self):
        """Test run() with missing topic."""
        from skills.research.swarm.run import run
        
        result = run({})
        
        assert result['status'] == 'error'
        assert 'topic' in result['message'].lower()


# =============================================================================
# Vulnerability Discovery Tests
# =============================================================================

class TestVulnDiscovery:
    """Test vulnerability discovery engine."""
    
    def test_target_type_enum(self):
        """Test TargetType enumeration."""
        from skills.research.vuln_discovery.run import TargetType
        
        assert TargetType.AUTO.value == "auto"
        assert TargetType.CODE.value == "code"
        assert TargetType.WEB.value == "web"
    
    def test_severity_enum(self):
        """Test Severity enumeration."""
        from skills.research.vuln_discovery.run import Severity
        
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
    
    def test_vuln_classes_mapping(self):
        """Test vulnerability classes mapping."""
        from skills.research.vuln_discovery.run import VULN_CLASSES, Severity
        
        sqli = VULN_CLASSES['sqli']
        assert sqli['cwe'] == "CWE-89"
        assert sqli['severity'] == Severity.CRITICAL
        
        xss = VULN_CLASSES['xss']
        assert xss['cwe'] == "CWE-79"
    
    def test_vulnerability_dataclass(self):
        """Test Vulnerability dataclass."""
        from skills.research.vuln_discovery.run import Vulnerability
        
        vuln = Vulnerability(
            id="VULN-001",
            title="SQL Injection",
            severity="CRITICAL",
            cvss=9.8,
            cwe="CWE-89",
            description="SQL injection in login",
            affected_component="/login",
        )
        
        assert vuln.id == "VULN-001"
        assert vuln.cvss == 9.8
    
    @patch('skills.research.vuln_discovery.run.KnowledgeBase')
    def test_vuln_discovery_init(self, mock_kb):
        """Test VulnDiscoveryEngine initialization."""
        from skills.research.vuln_discovery.run import VulnDiscoveryEngine
        
        engine = VulnDiscoveryEngine()
        
        assert engine.ollama_model == "mistral-nemo"
        mock_kb.assert_called_once()
    
    @patch('skills.research.vuln_discovery.run.KnowledgeBase')
    def test_detect_target_type_url(self, mock_kb):
        """Test target type detection for URLs."""
        from skills.research.vuln_discovery.run import VulnDiscoveryEngine, TargetType
        
        engine = VulnDiscoveryEngine()
        
        result = engine._detect_target_type("https://example.com")
        assert result == TargetType.WEB
    
    @patch('skills.research.vuln_discovery.run.KnowledgeBase')
    def test_detect_target_type_repo(self, mock_kb):
        """Test target type detection for repos."""
        from skills.research.vuln_discovery.run import VulnDiscoveryEngine, TargetType
        
        engine = VulnDiscoveryEngine()
        
        # .git extension triggers REPO detection
        result = engine._detect_target_type("https://github.com/test/repo.git")
        assert result == TargetType.REPO
        
        # github.com URL also triggers REPO
        result2 = engine._detect_target_type("https://github.com/test/repo")
        assert result2 == TargetType.REPO
    
    @patch('skills.research.vuln_discovery.run.KnowledgeBase')
    def test_static_analysis_patterns(self, mock_kb):
        """Test static analysis pattern matching."""
        from skills.research.vuln_discovery.run import CODE_PATTERNS
        import re
        
        # Test SQL injection pattern
        sqli_patterns = CODE_PATTERNS['sqli']
        test_code = 'cursor.execute(query + user_input)'
        
        matches = any(re.search(p, test_code) for p in sqli_patterns)
        assert matches
    
    def test_run_function_missing_target(self):
        """Test run() with missing target."""
        from skills.research.vuln_discovery.run import run
        
        result = run({})
        
        assert result['status'] == 'error'
        assert 'target' in result['message'].lower()


# =============================================================================
# Challenge Generator Tests
# =============================================================================

class TestChallengeGenerator:
    """Test CTF challenge generation."""
    
    def test_difficulty_enum(self):
        """Test Difficulty enumeration."""
        from skills.research.challenge_gen.run import Difficulty
        
        assert Difficulty.EASY.value == "easy"
        assert Difficulty.MEDIUM.value == "medium"
        assert Difficulty.HARD.value == "hard"
        assert Difficulty.INSANE.value == "insane"
    
    def test_category_enum(self):
        """Test Category enumeration."""
        from skills.research.challenge_gen.run import Category
        
        assert Category.WEB.value == "web"
        assert Category.PWN.value == "pwn"
        assert Category.WEB3.value == "web3"
    
    def test_ai_hardening_enum(self):
        """Test AIHardening enumeration."""
        from skills.research.challenge_gen.run import AIHardening
        
        assert AIHardening.NONE.value == "none"
        assert AIHardening.STANDARD.value == "standard"
        assert AIHardening.AGGRESSIVE.value == "aggressive"
    
    def test_difficulty_points_mapping(self):
        """Test difficulty to points mapping."""
        from skills.research.challenge_gen.run import DIFFICULTY_POINTS, Difficulty
        
        easy_range = DIFFICULTY_POINTS[Difficulty.EASY]
        assert easy_range == (100, 200)
        
        insane_range = DIFFICULTY_POINTS[Difficulty.INSANE]
        assert insane_range == (700, 1000)
    
    def test_challenge_templates(self):
        """Test challenge templates exist."""
        from skills.research.challenge_gen.run import CHALLENGE_TEMPLATES, Category
        
        assert 'sqli' in CHALLENGE_TEMPLATES
        assert 'xss' in CHALLENGE_TEMPLATES
        assert 'reentrancy' in CHALLENGE_TEMPLATES
        
        sqli = CHALLENGE_TEMPLATES['sqli']
        assert sqli['category'] == Category.WEB
        assert len(sqli['name_templates']) > 0
    
    def test_challenge_hint_dataclass(self):
        """Test ChallengeHint dataclass."""
        from skills.research.challenge_gen.run import ChallengeHint
        
        hint = ChallengeHint(cost=50, text="Look at the input")
        
        assert hint.cost == 50
        assert "input" in hint.text
    
    def test_ctf_challenge_dataclass(self):
        """Test CTFChallenge dataclass."""
        from skills.research.challenge_gen.run import CTFChallenge
        
        challenge = CTFChallenge(
            id="chal-001",
            name="Test Challenge",
            category="web",
            difficulty="medium",
            points=300,
            description="Find the flag!",
            flag="flag{test_flag}",
        )
        
        assert challenge.id == "chal-001"
        assert challenge.points == 300
        assert challenge.flag == "flag{test_flag}"
    
    def test_challenge_generator_init(self):
        """Test ChallengeGenerator initialization."""
        from skills.research.challenge_gen.run import ChallengeGenerator
        
        gen = ChallengeGenerator()
        
        assert gen.ollama_model == "mistral-nemo"
    
    def test_generate_flag(self):
        """Test flag generation."""
        from skills.research.challenge_gen.run import ChallengeGenerator, AIHardening
        
        gen = ChallengeGenerator()
        
        flag = gen._generate_flag(["sql", "inject"], AIHardening.STANDARD)
        
        assert flag.startswith("flag{")
        assert flag.endswith("}")
        assert len(flag) > 10
    
    def test_generate_flag_aggressive_hardening(self):
        """Test flag generation with aggressive hardening."""
        from skills.research.challenge_gen.run import ChallengeGenerator, AIHardening
        
        gen = ChallengeGenerator()
        
        flag = gen._generate_flag(["test"], AIHardening.AGGRESSIVE)
        
        assert "h4rd3n3d" in flag
    
    def test_generate_hints(self):
        """Test hint generation."""
        from skills.research.challenge_gen.run import ChallengeGenerator, Difficulty
        
        gen = ChallengeGenerator()
        
        hints = gen._generate_hints("sqli", Difficulty.MEDIUM)
        
        assert len(hints) == 3
        assert hints[0].cost < hints[1].cost < hints[2].cost
    
    def test_run_function_missing_params(self):
        """Test run() with missing parameters."""
        from skills.research.challenge_gen.run import run
        
        result = run({})
        
        assert result['status'] == 'error'
        assert 'finding' in result['message'].lower() or 'vuln_type' in result['message'].lower()
    
    def test_run_function_with_vuln_type(self):
        """Test run() with vuln_type parameter."""
        from skills.research.challenge_gen.run import run
        
        with patch('skills.research.challenge_gen.run.ChallengeGenerator._query_llm') as mock_llm:
            mock_llm.return_value = ""
            
            result = run({
                'vuln_type': 'sqli',
                'difficulty': 'easy',
            })
        
        assert result['status'] == 'success'
        assert 'challenge' in result
        assert result['challenge']['category'] == 'web'


# =============================================================================
# Integration Tests
# =============================================================================

class TestResearchIntegration:
    """Integration tests for research components."""
    
    @patch('skills.research.knowledge_base.chromadb')
    def test_search_knowledge_helper(self, mock_chromadb):
        """Test search_knowledge helper function."""
        from skills.research.knowledge_base import search_knowledge
        
        mock_client = Mock()
        mock_collection = Mock()
        mock_chromadb.PersistentClient.return_value = mock_client
        mock_client.get_or_create_collection.return_value = mock_collection
        
        mock_collection.query.return_value = {
            'ids': [['doc-001_0']],
            'documents': [['SQL injection content']],
            'metadatas': [[{
                'document_id': 'doc-001',
                'title': 'SQLi', 
                'source': 'test', 
                'source_type': 'manual', 
                'url': '', 
                'tags': '[]'
            }]],
            'distances': [[0.1]],
        }
        
        results = search_knowledge("SQL injection")
        
        # search_knowledge returns list of dicts, not SearchResult objects
        assert len(results) == 1
        assert results[0]['title'] == 'SQLi'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
