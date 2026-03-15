"""CTF-Katana MCP Server.

A locally deployed Model Context Protocol server that orchestrates autonomous
agents backed by **Ollama** to solve CTF challenges.  It uses the original
Katana README as a living knowledge base and exposes agent skills as MCP tools.

Run with::

    katana-server            # via the installed entry-point
    python -m katana.server  # directly
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from katana.knowledge_base import KnowledgeBase, category_for
from katana.skills import analysis, crypto, forensics, pwn, recon, reversing, stego, web
from katana.agents.analyzer import AnalyzerAgent
from katana.agents.planner import PlannerAgent
from katana.agents.executor import ExecutorAgent
from katana.agents.reporter import ReporterAgent

# ---------------------------------------------------------------------------
# Initialise the MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "katana",
    instructions=(
        "CTF-Katana: an agentic AI system for solving Capture-The-Flag "
        "challenges.  Use the tools below to analyse artifacts, search the "
        "knowledge base, run crypto/stego/forensics/web/pwn/reversing/recon "
        "operations, and orchestrate autonomous solving agents backed by "
        "Ollama."
    ),
)

# Ollama configuration (overridable via environment variables)
OLLAMA_MODEL = os.environ.get("KATANA_OLLAMA_MODEL", "mistral")
OLLAMA_HOST = os.environ.get("KATANA_OLLAMA_HOST", "http://localhost:11434")

# ---------------------------------------------------------------------------
# Knowledge-base (lazy-loaded singleton)
# ---------------------------------------------------------------------------

_kb: KnowledgeBase | None = None


def _get_kb() -> KnowledgeBase:
    global _kb
    if _kb is None:
        readme = Path(__file__).resolve().parent.parent.parent / "README.md"
        _kb = KnowledgeBase.from_readme(readme)
    return _kb


# =========================================================================
# MCP Resources – expose the knowledge base
# =========================================================================

@mcp.resource("katana://knowledge/summary")
def kb_summary() -> str:
    """Human-readable summary of the CTF-Katana knowledge base."""
    return _get_kb().summary()


@mcp.resource("katana://knowledge/sections")
def kb_sections() -> str:
    """List all knowledge-base section titles."""
    return json.dumps(_get_kb().list_sections(), indent=2)


@mcp.resource("katana://knowledge/categories")
def kb_categories() -> str:
    """List canonical CTF categories."""
    return json.dumps(_get_kb().categories, indent=2)


# =========================================================================
# MCP Prompts – pre-defined prompt templates
# =========================================================================

@mcp.prompt()
def analyze_challenge(artifact_path: str) -> str:
    """Prompt: analyse a CTF challenge artifact."""
    return (
        f"Use the `analyze_artifact` tool to inspect the file at "
        f"`{artifact_path}`, then search the knowledge base for relevant "
        f"techniques and suggest a solving strategy."
    )


@mcp.prompt()
def solve_challenge(artifact_path: str, challenge_name: str = "CTF Challenge") -> str:
    """Prompt: end-to-end autonomous solve."""
    return (
        f"Solve the CTF challenge '{challenge_name}'.\n"
        f"1. Analyze the artifact at `{artifact_path}`.\n"
        f"2. Search the knowledge base for relevant techniques.\n"
        f"3. Create a plan using `agent_plan`.\n"
        f"4. Execute each step using the skill tools.\n"
        f"5. Generate a write-up with `agent_report`."
    )


# =========================================================================
# MCP Tools – Knowledge base
# =========================================================================

@mcp.tool()
def search_knowledge(query: str, limit: int = 10) -> str:
    """Search the CTF-Katana knowledge base for tools and techniques.

    Args:
        query: Keyword to search for (e.g. "xor", "steghide", "buffer overflow").
        limit: Maximum number of results.
    """
    results = _get_kb().search(query, limit=limit)
    if not results:
        return "No matching knowledge-base entries."
    entries = []
    for r in results:
        entry = {"name": r.name, "description": r.description[:200]}
        if r.commands:
            entry["commands"] = r.commands[:3]
        if r.urls:
            entry["urls"] = r.urls[:3]
        entries.append(entry)
    return json.dumps(entries, indent=2)


@mcp.tool()
def get_knowledge_section(title: str) -> str:
    """Retrieve raw content for a specific knowledge-base section.

    Args:
        title: Section title (e.g. "Cryptography", "Steganography").
    """
    section = _get_kb().get_section(title)
    if section is None:
        return f"Section '{title}' not found. Available: {_get_kb().list_sections()}"
    return section.raw_text[:5000]


@mcp.tool()
def list_knowledge_categories() -> str:
    """List the canonical CTF categories in the knowledge base."""
    kb = _get_kb()
    result: dict[str, list[str]] = {}
    for section in kb.sections:
        cat = category_for(section.title)
        result.setdefault(cat, []).append(section.title)
    return json.dumps(result, indent=2)


# =========================================================================
# MCP Tools – Analysis skill
# =========================================================================

@mcp.tool()
def analyze_artifact(path: str) -> str:
    """Analyse a challenge file: detect type, encodings, show hex header.

    Args:
        path: Absolute path to the file to analyse.
    """
    return json.dumps(analysis.analyze_file(path), indent=2)


@mcp.tool()
def identify_encoding(data: str) -> str:
    """Guess the encoding(s) of a given data string.

    Args:
        data: The data string to analyse.
    """
    return json.dumps(analysis.identify_encoding(data), indent=2)


# =========================================================================
# MCP Tools – Crypto skill
# =========================================================================

@mcp.tool()
def crypto_rot13(text: str) -> str:
    """Apply ROT-13 to text.

    Args:
        text: The text to transform.
    """
    return crypto.rot13(text)


@mcp.tool()
def crypto_caesar(text: str, shift: int) -> str:
    """Apply a Caesar cipher shift.

    Args:
        text: The text to shift.
        shift: Number of positions to shift (1-25).
    """
    return crypto.caesar(text, shift)


@mcp.tool()
def crypto_caesar_bruteforce(text: str) -> str:
    """Try all 25 Caesar shifts and return results.

    Args:
        text: The ciphertext.
    """
    return json.dumps(crypto.caesar_bruteforce(text), indent=2)


@mcp.tool()
def crypto_xor_bruteforce(data_hex: str) -> str:
    """Brute-force single-byte XOR on hex-encoded data.

    Args:
        data_hex: Hex-encoded ciphertext (e.g. "4a5b6c").
    """
    return json.dumps(crypto.xor_bruteforce(data_hex), indent=2)


@mcp.tool()
def crypto_base64_decode(data: str) -> str:
    """Decode a Base-64 string.

    Args:
        data: Base-64 encoded string.
    """
    return crypto.base64_decode(data)


@mcp.tool()
def crypto_base64_encode(data: str) -> str:
    """Encode a string to Base-64.

    Args:
        data: Plain text to encode.
    """
    return crypto.base64_encode(data)


@mcp.tool()
def crypto_vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt Vigenère ciphertext with a known key.

    Args:
        ciphertext: The encrypted text.
        key: The Vigenère key.
    """
    return crypto.vigenere_decrypt(ciphertext, key)


@mcp.tool()
def crypto_hex_decode(data: str) -> str:
    """Decode hex-encoded data to text.

    Args:
        data: Hex string (e.g. "48656c6c6f").
    """
    return crypto.hex_decode(data)


# =========================================================================
# MCP Tools – Steganography skill
# =========================================================================

@mcp.tool()
def stego_strings(path: str, min_length: int = 6) -> str:
    """Run ``strings`` on a file.

    Args:
        path: Path to the file.
        min_length: Minimum string length to report.
    """
    return stego.run_strings(path, min_length=min_length)


@mcp.tool()
def stego_exiftool(path: str) -> str:
    """Extract metadata with exiftool.

    Args:
        path: Path to the image/file.
    """
    return stego.run_exiftool(path)


@mcp.tool()
def stego_binwalk(path: str) -> str:
    """Search for embedded files with binwalk.

    Args:
        path: Path to the file.
    """
    return stego.run_binwalk(path)


@mcp.tool()
def stego_steghide(path: str, passphrase: str = "") -> str:
    """Attempt steghide extraction with a passphrase (empty by default).

    Args:
        path: Path to the image.
        passphrase: Passphrase (try empty string first!).
    """
    return stego.run_steghide_extract(path, passphrase=passphrase)


@mcp.tool()
def stego_zsteg(path: str) -> str:
    """Run zsteg on a PNG/BMP file.

    Args:
        path: Path to the image.
    """
    return stego.run_zsteg(path)


# =========================================================================
# MCP Tools – Forensics skill
# =========================================================================

@mcp.tool()
def forensics_file_magic(path: str) -> str:
    """Get the file type via magic bytes.

    Args:
        path: Path to the file.
    """
    return forensics.check_file_magic(path)


@mcp.tool()
def forensics_foremost(path: str) -> str:
    """Carve files from a binary blob using foremost.

    Args:
        path: Path to the file.
    """
    return forensics.run_foremost(path)


@mcp.tool()
def forensics_pngcheck(path: str) -> str:
    """Validate a PNG file with pngcheck.

    Args:
        path: Path to the PNG file.
    """
    return forensics.run_pngcheck(path)


@mcp.tool()
def forensics_pdf_text(path: str) -> str:
    """Extract text from a PDF.

    Args:
        path: Path to the PDF file.
    """
    return forensics.pdf_to_text(path)


# =========================================================================
# MCP Tools – Web skill
# =========================================================================

@mcp.tool()
def web_check_headers(url: str) -> str:
    """Fetch HTTP response headers from a URL.

    Args:
        url: Target URL.
    """
    return web.check_headers(url)


@mcp.tool()
def web_robots_txt(url: str) -> str:
    """Fetch /robots.txt from a web server.

    Args:
        url: Base URL.
    """
    return web.check_robots_txt(url)


@mcp.tool()
def web_decode_jwt(token: str) -> str:
    """Decode a JWT token (without verification) for inspection.

    Args:
        token: The JWT string.
    """
    return json.dumps(web.decode_jwt(token), indent=2)


# =========================================================================
# MCP Tools – Reversing skill
# =========================================================================

@mcp.tool()
def reversing_disassemble(path: str) -> str:
    """Disassemble a binary with objdump.

    Args:
        path: Path to the binary.
    """
    output = reversing.disassemble(path)
    # Truncate large output
    if len(output) > 10_000:
        output = output[:10_000] + "\n... (truncated)"
    return output


@mcp.tool()
def reversing_symbols(path: str) -> str:
    """List symbols in a binary.

    Args:
        path: Path to the binary.
    """
    return reversing.show_symbols(path)


@mcp.tool()
def reversing_elf_info(path: str) -> str:
    """Show ELF header information.

    Args:
        path: Path to the ELF binary.
    """
    return reversing.show_elf_info(path)


# =========================================================================
# MCP Tools – Pwn skill
# =========================================================================

@mcp.tool()
def pwn_checksec(path: str) -> str:
    """Check binary security protections (NX, ASLR, canary, etc.).

    Args:
        path: Path to the binary.
    """
    return pwn.checksec(path)


@mcp.tool()
def pwn_rop_gadgets(path: str) -> str:
    """Search for ROP gadgets in a binary.

    Args:
        path: Path to the binary.
    """
    output = pwn.find_rop_gadgets(path)
    if len(output) > 10_000:
        output = output[:10_000] + "\n... (truncated)"
    return output


@mcp.tool()
def pwn_pattern_create(length: int) -> str:
    """Generate a cyclic pattern for buffer-overflow offset detection.

    Args:
        length: Desired pattern length.
    """
    return pwn.pattern_create(length)


@mcp.tool()
def pwn_got(path: str) -> str:
    """Display the GOT entries of an ELF binary.

    Args:
        path: Path to the binary.
    """
    return pwn.show_got(path)


# =========================================================================
# MCP Tools – Recon skill
# =========================================================================

@mcp.tool()
def recon_nmap(target: str, ports: str = "-") -> str:
    """Run an nmap service scan against a target.

    Args:
        target: IP address or hostname.
        ports: Port specification (default: all ports).
    """
    return recon.nmap_scan(target, ports=ports)


@mcp.tool()
def recon_whois(target: str) -> str:
    """Run a WHOIS lookup.

    Args:
        target: Domain or IP.
    """
    return recon.whois_lookup(target)


@mcp.tool()
def recon_dig(domain: str, record_type: str = "ANY") -> str:
    """DNS lookup via dig.

    Args:
        domain: Domain name.
        record_type: DNS record type (A, AAAA, MX, TXT, ANY, etc.).
    """
    return recon.dig_lookup(domain, record_type)


# =========================================================================
# MCP Tools – Agent orchestration (Ollama-backed)
# =========================================================================

@mcp.tool()
async def agent_analyze(artifact_path: str) -> str:
    """Use the Analyzer agent (Ollama) to inspect and classify a challenge artifact.

    Analyses the file, searches the knowledge base for relevant techniques,
    and returns a structured JSON analysis.

    Args:
        artifact_path: Path to the challenge file.
    """
    # 1. Gather raw artifact info
    file_info = analysis.analyze_file(artifact_path)

    # 2. Try to find relevant knowledge
    kb = _get_kb()
    file_type = file_info.get("file_type", "")
    kb_results = kb.search(file_type, limit=5)
    kb_context = "\n".join(
        f"- {e.name}: {e.description[:120]}" for e in kb_results
    )

    # 3. Run the Analyzer agent
    agent = AnalyzerAgent(model=OLLAMA_MODEL, ollama_host=OLLAMA_HOST)
    result = await agent.aanalyze(json.dumps(file_info, indent=2), kb_context)
    return json.dumps(result, indent=2)


@mcp.tool()
async def agent_plan(analysis_json: str) -> str:
    """Use the Planner agent (Ollama) to create a step-by-step solving strategy.

    Args:
        analysis_json: JSON string from a prior ``agent_analyze`` call.
    """
    # Find relevant knowledge for the category
    kb = _get_kb()
    try:
        info = json.loads(analysis_json)
        category = info.get("category", "")
    except (json.JSONDecodeError, AttributeError):
        category = ""

    kb_sections = kb.sections_for_category(category) if category else []
    kb_context = "\n".join(
        f"[{s.title}] {', '.join(e.name for e in s.entries[:10])}"
        for s in kb_sections[:3]
    )

    agent = PlannerAgent(model=OLLAMA_MODEL, ollama_host=OLLAMA_HOST)
    result = await agent.aplan(analysis_json, kb_context)
    return json.dumps(result, indent=2)


@mcp.tool()
async def agent_interpret(step_description: str, tool_output: str) -> str:
    """Use the Executor agent (Ollama) to interpret a tool's output.

    Args:
        step_description: What the step was trying to do.
        tool_output: Raw output from the tool.
    """
    agent = ExecutorAgent(model=OLLAMA_MODEL, ollama_host=OLLAMA_HOST)
    result = await agent.ainterpret(step_description, tool_output)
    return json.dumps(result, indent=2)


@mcp.tool()
async def agent_report(execution_log: str, challenge_name: str = "CTF Challenge") -> str:
    """Use the Reporter agent (Ollama) to generate a write-up and optional exploit PoC.

    Args:
        execution_log: Full log of the solving session.
        challenge_name: Name of the challenge.
    """
    agent = ReporterAgent(model=OLLAMA_MODEL, ollama_host=OLLAMA_HOST)
    result = await agent.agenerate(execution_log, challenge_name)
    return json.dumps(result, indent=2)


# =========================================================================
# Entry-point
# =========================================================================

def main() -> None:
    """Run the Katana MCP server (stdio transport)."""
    mcp.run()


if __name__ == "__main__":
    main()
