import sys
from pathlib import Path

# Fix path for standalone execution
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from tools.strings_runner import run_strings
from tools.exiftool_runner import run_exiftool
from tools.binwalk_scan import binwalk_scan
from tools.steghide_runner import steghide_extract
from tools.zsteg_runner import run_zsteg

_ACTIONS = {
    "strings": lambda i: run_strings(i["path"], min_length=int(i.get("min_length", 6))),
    "exiftool": lambda i: run_exiftool(i["path"]),
    "binwalk": lambda i: binwalk_scan(i["path"]),
    "steghide": lambda i: steghide_extract(i["path"], i.get("passphrase", "")),
    "zsteg": lambda i: run_zsteg(i["path"]),
}

def run(params: dict) -> dict:
    """Skill entry-point called by the registry."""
    action = params.get("action", "")
    fn = _ACTIONS.get(action)
    if fn is None:
        return {
            "status": False,
            "summary": f"Unknown action: {action}",
            "result": {"available": list(_ACTIONS)}
        }
    try:
        data = fn(params)
        return {
            "status": True,
            "summary": f"Executed {action} stego analysis.",
            "result": data
        }
    except Exception as exc:
        return {"status": False, "summary": str(exc), "result": {"error": str(exc)}}

if __name__ == "__main__":
    if len(sys.argv) > 2:
        print(run({"action": sys.argv[1], "path": sys.argv[2]}))
    else:
        print("Usage: python run.py <action> <filepath>")
