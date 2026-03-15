"""CTF-Katana MCP Server – the central orchestrator.

Exposes skills, tools, knowledge-base resources, and agent endpoints via the
Model Context Protocol using FastMCP (stdio transport).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from context.knowledge_base import KnowledgeBase
from server.registry import discover_skills

# ---------------------------------------------------------------------------
# Initialise
# ---------------------------------------------------------------------------

mcp = FastMCP("katana")

_REPO_ROOT = Path(__file__).resolve().parent.parent
_kb = KnowledgeBase.from_readme(_REPO_ROOT / "README.md")
_skills = discover_skills(_REPO_ROOT / "skills")

_OLLAMA_MODEL = os.environ.get("KATANA_OLLAMA_MODEL", "mistral")
_OLLAMA_HOST = os.environ.get("KATANA_OLLAMA_HOST", "http://localhost:11434")


# ===================================================================
# MCP Resources – read-only knowledge-base views
# ===================================================================

@mcp.resource("katana://knowledge/summary")
def kb_summary() -> str:
    """Human-readable summary of the entire knowledge base."""
    return _kb.summary()


@mcp.resource("katana://knowledge/sections")
def kb_sections() -> str:
    """List every section title in the knowledge base."""
    return json.dumps(_kb.list_sections())


@mcp.resource("katana://knowledge/categories")
def kb_categories() -> str:
    """List canonical CTF categories."""
    return json.dumps(_kb.categories)


# ===================================================================
# MCP Prompts – pre-built templates
# ===================================================================

@mcp.prompt()
def analyze_challenge(artifact_path: str) -> str:
    """Prompt: analyse a challenge artifact end-to-end."""
    return (
        f"Analyse the CTF challenge artifact at: {artifact_path}\n\n"
        "1. Use `analyze_artifact` to inspect the file.\n"
        "2. Use `search_knowledge` with the detected category.\n"
        "3. Summarise findings and suggest next steps.\n"
    )


@mcp.prompt()
def solve_challenge(artifact_path: str, challenge_name: str = "CTF Challenge") -> str:
    """Prompt: solve a challenge from start to finish."""
    return (
        f"Solve the CTF challenge **{challenge_name}** "
        f"(artifact: {artifact_path}).\n\n"
        "Follow the Katana workflow:\n"
        "1. Analyse the artifact.\n"
        "2. Search the knowledge base.\n"
        "3. Plan a solving strategy.\n"
        "4. Execute each step.\n"
        "5. Interpret results.\n"
        "6. Generate a write-up.\n"
    )


# ===================================================================
# MCP Tools – Knowledge Base
# ===================================================================

@mcp.tool()
def search_knowledge(query: str, limit: int = 10) -> str:
    """Search the CTF-Katana knowledge base for tools and techniques."""
    entries = _kb.search(query, limit=limit)
    if not entries:
        return f"No results for '{query}'."
    lines: list[str] = []
    for e in entries:
        lines.append(f"• **{e.name}**: {e.description}")
        if e.commands:
            lines.append(f"  Commands: {', '.join(e.commands[:3])}")
        if e.urls:
            lines.append(f"  URLs: {', '.join(e.urls[:2])}")
    return "\n".join(lines)


@mcp.tool()
def get_knowledge_section(title: str) -> str:
    """Retrieve a specific knowledge-base section by title."""
    sec = _kb.get_section(title)
    if sec is None:
        return f"Section '{title}' not found. Use list_knowledge_categories to browse."
    return sec.raw_text[:4000]


@mcp.tool()
def list_knowledge_categories() -> str:
    """List all CTF categories and their sections."""
    lines: list[str] = []
    for cat in _kb.categories:
        secs = _kb.sections_for_category(cat)
        names = ", ".join(s.title for s in secs)
        lines.append(f"**{cat}**: {names}")
    return "\n".join(lines)


@mcp.tool()
def list_skills() -> str:
    """List all registered skills and their descriptions."""
    lines: list[str] = []
    for name, skill in sorted(_skills.items()):
        lines.append(f"• **{name}** [{skill.meta.category}]: {skill.meta.description}")
    return "\n".join(lines)


@mcp.tool()
def get_skill_prompt(skill_name: str) -> str:
    """Retrieve the LLM reasoning prompt for a skill."""
    skill = _skills.get(skill_name)
    if skill is None:
        return f"Skill '{skill_name}' not found."
    return skill.prompt or "(no prompt defined)"


@mcp.tool()
def run_skill(skill_name: str, inputs_json: str = "{}") -> str:
    """Execute a skill by name with the given JSON inputs."""
    skill = _skills.get(skill_name)
    if skill is None:
        return json.dumps({"error": f"Skill '{skill_name}' not found."})
    if skill.run is None:
        return json.dumps({"error": f"Skill '{skill_name}' has no run function."})
    try:
        inputs = json.loads(inputs_json)
    except json.JSONDecodeError as exc:
        return json.dumps({"error": f"Invalid JSON inputs: {exc}"})
    try:
        result = skill.run(inputs)
        return json.dumps(result, default=str)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ===================================================================
# MCP Tools – Artifact Analysis
# ===================================================================

@mcp.tool()
def analyze_artifact(path: str) -> str:
    """Analyse a challenge file – detect type, size, encoding, hex header."""
    skill = _skills.get("analysis")
    if skill and skill.run:
        return json.dumps(skill.run({"path": path}), default=str)
    return json.dumps({"error": "analysis skill not loaded"})


@mcp.tool()
def identify_encoding(data: str) -> str:
    """Guess the encoding(s) present in a text string."""
    skill = _skills.get("analysis")
    if skill and skill.run:
        return json.dumps(skill.run({"data": data}), default=str)
    return json.dumps({"error": "analysis skill not loaded"})


# ===================================================================
# MCP Tools – Crypto
# ===================================================================

def _crypto(action: str, **kwargs) -> str:
    skill = _skills.get("crypto_solver")
    if skill and skill.run:
        return json.dumps(skill.run({"action": action, **kwargs}), default=str)
    return json.dumps({"error": "crypto_solver skill not loaded"})


@mcp.tool()
def crypto_rot13(text: str) -> str:
    """Apply ROT-13."""
    return _crypto("rot13", text=text)

@mcp.tool()
def crypto_caesar(text: str, shift: int) -> str:
    """Caesar-shift *text* by *shift* positions."""
    return _crypto("caesar", text=text, shift=str(shift))

@mcp.tool()
def crypto_caesar_bruteforce(text: str) -> str:
    """Try all 25 Caesar shifts."""
    return _crypto("caesar_bruteforce", text=text)

@mcp.tool()
def crypto_xor_bruteforce(data_hex: str) -> str:
    """Single-byte XOR brute-force (hex input)."""
    return _crypto("xor_bruteforce", data_hex=data_hex)

@mcp.tool()
def crypto_base64_decode(data: str) -> str:
    """Decode a Base-64 string."""
    return _crypto("base64_decode", text=data)

@mcp.tool()
def crypto_base64_encode(data: str) -> str:
    """Encode a string to Base-64."""
    return _crypto("base64_encode", text=data)

@mcp.tool()
def crypto_vigenere_decrypt(text: str, key: str) -> str:
    """Decrypt a Vigenère cipher with a known key."""
    return _crypto("vigenere_decrypt", text=text, key=key)

@mcp.tool()
def crypto_hex_decode(data: str) -> str:
    """Decode a hexadecimal string."""
    return _crypto("hex_decode", text=data)


# ===================================================================
# MCP Tools – Steganography
# ===================================================================

def _stego(action: str, **kwargs) -> str:
    skill = _skills.get("stego_solver")
    if skill and skill.run:
        return json.dumps(skill.run({"action": action, **kwargs}), default=str)
    return json.dumps({"error": "stego_solver skill not loaded"})

@mcp.tool()
def stego_strings(path: str) -> str:
    """Extract printable strings from a file."""
    return _stego("strings", path=path)

@mcp.tool()
def stego_exiftool(path: str) -> str:
    """Extract metadata with exiftool."""
    return _stego("exiftool", path=path)

@mcp.tool()
def stego_binwalk(path: str) -> str:
    """Scan for embedded files with binwalk."""
    return _stego("binwalk", path=path)

@mcp.tool()
def stego_steghide(path: str, passphrase: str = "") -> str:
    """Extract hidden data with steghide."""
    return _stego("steghide", path=path, passphrase=passphrase)

@mcp.tool()
def stego_zsteg(path: str) -> str:
    """Run zsteg on a PNG/BMP file."""
    return _stego("zsteg", path=path)


# ===================================================================
# MCP Tools – Forensics
# ===================================================================

def _forensics(action: str, **kwargs) -> str:
    skill = _skills.get("forensics")
    if skill and skill.run:
        return json.dumps(skill.run({"action": action, **kwargs}), default=str)
    return json.dumps({"error": "forensics skill not loaded"})

@mcp.tool()
def forensics_file_magic(path: str) -> str:
    """Identify a file's type via magic bytes."""
    return _forensics("file_magic", path=path)

@mcp.tool()
def forensics_foremost(path: str) -> str:
    """Carve embedded files with foremost."""
    return _forensics("foremost", path=path)

@mcp.tool()
def forensics_pngcheck(path: str) -> str:
    """Validate a PNG file."""
    return _forensics("pngcheck", path=path)

@mcp.tool()
def forensics_pdf_text(path: str) -> str:
    """Extract text from a PDF."""
    return _forensics("pdf_text", path=path)


# ===================================================================
# MCP Tools – Web
# ===================================================================

def _web(action: str, **kwargs) -> str:
    skill = _skills.get("web_exploit")
    if skill and skill.run:
        return json.dumps(skill.run({"action": action, **kwargs}), default=str)
    return json.dumps({"error": "web_exploit skill not loaded"})

@mcp.tool()
def web_check_headers(url: str) -> str:
    """Fetch HTTP response headers."""
    return _web("check_headers", url=url)

@mcp.tool()
def web_robots_txt(url: str) -> str:
    """Fetch /robots.txt."""
    return _web("robots_txt", url=url)

@mcp.tool()
def web_decode_jwt(token: str) -> str:
    """Decode a JWT (without verification)."""
    return _web("decode_jwt", token=token)


# ===================================================================
# MCP Tools – Reverse Engineering
# ===================================================================

def _reversing(action: str, **kwargs) -> str:
    skill = _skills.get("reverse_engineering")
    if skill and skill.run:
        return json.dumps(skill.run({"action": action, **kwargs}), default=str)
    return json.dumps({"error": "reverse_engineering skill not loaded"})

@mcp.tool()
def reversing_disassemble(path: str) -> str:
    """Disassemble a binary."""
    return _reversing("disassemble", path=path)

@mcp.tool()
def reversing_symbols(path: str) -> str:
    """List symbols in a binary."""
    return _reversing("symbols", path=path)

@mcp.tool()
def reversing_elf_info(path: str) -> str:
    """Show ELF header information."""
    return _reversing("elf_info", path=path)


# ===================================================================
# MCP Tools – Binary Exploitation / Pwn
# ===================================================================

def _pwn(action: str, **kwargs) -> str:
    skill = _skills.get("binary_exploit")
    if skill and skill.run:
        return json.dumps(skill.run({"action": action, **kwargs}), default=str)
    return json.dumps({"error": "binary_exploit skill not loaded"})

@mcp.tool()
def pwn_checksec(path: str) -> str:
    """Check binary protections."""
    return _pwn("checksec", path=path)

@mcp.tool()
def pwn_rop_gadgets(path: str) -> str:
    """Search for ROP gadgets."""
    return _pwn("rop_gadgets", path=path)

@mcp.tool()
def pwn_pattern_create(length: int = 200) -> str:
    """Generate a cyclic pattern for offset finding."""
    return _pwn("pattern_create", length=str(length))

@mcp.tool()
def pwn_got(path: str) -> str:
    """Display the GOT of an ELF binary."""
    return _pwn("got", path=path)


# ===================================================================
# MCP Tools – Reconnaissance
# ===================================================================

def _recon(action: str, **kwargs) -> str:
    skill = _skills.get("recon")
    if skill and skill.run:
        return json.dumps(skill.run({"action": action, **kwargs}), default=str)
    return json.dumps({"error": "recon skill not loaded"})

@mcp.tool()
def recon_nmap(target: str, ports: str = "-") -> str:
    """Run an nmap service scan."""
    return _recon("nmap", target=target, ports=ports)

@mcp.tool()
def recon_whois(target: str) -> str:
    """WHOIS lookup."""
    return _recon("whois", target=target)

@mcp.tool()
def recon_dig(domain: str, record_type: str = "ANY") -> str:
    """DNS lookup via dig."""
    return _recon("dig", target=domain, record_type=record_type)


# ===================================================================
# MCP Tools – Agent Orchestration (async, Ollama-backed)
# ===================================================================

@mcp.tool()
async def agent_analyze(artifact_path: str) -> str:
    """Analyse a challenge artifact using the Analyzer agent (Ollama)."""
    from agents.analyzer import AnalyzerAgent

    # Gather context
    info = json.loads(analyze_artifact(artifact_path))
    category = info.get("category", "")
    kb_context = search_knowledge(category) if category else ""

    agent = AnalyzerAgent(model=_OLLAMA_MODEL, ollama_host=_OLLAMA_HOST)
    result = await agent.aanalyze(json.dumps(info), kb_context)
    return json.dumps(result, default=str)


@mcp.tool()
async def agent_plan(analysis_json: str) -> str:
    """Generate a solving plan from an analysis (Ollama)."""
    from agents.planner import PlannerAgent

    agent = PlannerAgent(model=_OLLAMA_MODEL, ollama_host=_OLLAMA_HOST)
    try:
        analysis = json.loads(analysis_json)
        category = analysis.get("category", "")
    except (json.JSONDecodeError, AttributeError):
        category = ""
    kb_context = search_knowledge(category) if category else ""
    result = await agent.aplan(analysis_json, kb_context)
    return json.dumps(result, default=str)


@mcp.tool()
async def agent_interpret(step_description: str, tool_output: str) -> str:
    """Interpret tool output and decide next action (Ollama)."""
    from agents.executor import ExecutorAgent

    agent = ExecutorAgent(model=_OLLAMA_MODEL, ollama_host=_OLLAMA_HOST)
    result = await agent.ainterpret(step_description, tool_output)
    return json.dumps(result, default=str)


@mcp.tool()
async def agent_report(execution_log: str, challenge_name: str = "CTF Challenge") -> str:
    """Generate a write-up and exploit PoC (Ollama)."""
    from agents.reporter import ReporterAgent

    agent = ReporterAgent(model=_OLLAMA_MODEL, ollama_host=_OLLAMA_HOST)
    result = await agent.agenerate(execution_log, challenge_name)
    return json.dumps(result, default=str)


# ===================================================================
# Entry-point
# ===================================================================

def main() -> None:
    """Run the Katana MCP server (stdio transport)."""
    mcp.run()


if __name__ == "__main__":
    main()
