import sys
import os
from pathlib import Path
from typing import Dict, Any

# Absolute import from root if needed, or relative if it was packaged.
# Since 'tools' is at root, we'll keep it as is but add standalone support.
try:
    from tools import detect_file_type, hex_dump, read_text_safe
except ImportError:
    # Manual path fix for standalone
    project_root = Path(__file__).resolve().parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from tools import detect_file_type, hex_dump, read_text_safe

def analyze_file(path: str) -> dict:
    """Analyze a file and return a structured summary."""
    p = Path(path)
    if not p.exists():
        return {"error": f"File not found: {path}"}

    info: dict = {
        "path": str(p),
        "file_type": detect_file_type(path),
        "size_bytes": p.stat().st_size,
    }

    text = read_text_safe(path)
    if text is not None:
        info["is_text"] = True
        info["preview"] = text[:2000]
        info["encodings"] = identify_encoding(text[:500])
    else:
        info["is_text"] = False
        info["hex_dump"] = hex_dump(path, length=256)

    return info

def identify_encoding(data: str) -> list[str]:
    """Guess possible encodings present in *data*."""
    guesses: list[str] = []
    import re # Ensure re is imported
    if re.fullmatch(r"[A-Za-z0-9+/=\s]+", data):
        guesses.append("base64")
    if re.fullmatch(r"[0-9a-fA-F\s]+", data):
        guesses.append("hex")
    if re.search(r"\\x[0-9a-fA-F]{2}", data):
        guesses.append("escaped_hex")
    if re.search(r"&#?\w+;", data):
        guesses.append("html_entities")
    if re.fullmatch(r"[01\s]+", data):
        guesses.append("binary")
    if re.search(r"%[0-9a-fA-F]{2}", data):
        guesses.append("url_encoded")
    return guesses

def run(params: dict) -> dict:
    """Skill entry-point called by the registry."""
    path = params.get("path", "")
    data = params.get("data", "")

    try:
        if path:
            result = analyze_file(path)
            if "error" in result:
                return {"status": False, "summary": result["error"], "result": {"error": result["error"]}}
            return {
                "status": True,
                "summary": f"Analyzed file: {path}",
                "result": result
            }
        if data:
            result = identify_encoding(data)
            return {
                "status": True,
                "summary": "Identified possible encodings in data.",
                "result": {"encodings": result}
            }
        return {
            "status": False,
            "summary": "Provide 'path' or 'data' in params.",
            "result": {}
        }
    except Exception as exc:
        return {
            "status": False, 
            "summary": str(exc),
            "result": {"error": str(exc)}
        }

if __name__ == "__main__":
    # Example standalone usage
    if len(sys.argv) > 1:
        print(run({"path": sys.argv[1]}))
    else:
        print("Usage: python run.py <filepath>")
