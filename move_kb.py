import sys
from pathlib import Path

def main():
    root = Path(r"c:\Users\mahes\OneDrive\Desktop\Python-Projects\ctf-katana")
    readme_path = root / "README.md"
    kb_path = root / "KNOWLEDGE_BASE.md"

    if not readme_path.exists():
        print(f"Error: {readme_path} not found")
        sys.exit(1)

    lines = readme_path.read_text(encoding="utf-8").splitlines(keepends=True)

    # We want to keep everything up to line 191 (index 190)
    # Line 192 (index 191) is the separator "---"
    # Line 193 (index 192) is another "---" or blank according to previous view
    # Line 194 (index 193) is the start of the KB notice

    # Let's find exactly where " Everything below is the original CTF-Katana knowledge base" starts
    split_idx = -1
    for i, line in enumerate(lines):
        if "Everything below is the original CTF-Katana" in line:
            split_idx = i
            break

    if split_idx == -1:
        print("Error: Could not find KB start marker in README.md")
        sys.exit(1)

    # Backup the README first
    (root / "README.md.bak").write_text("".join(lines), encoding="utf-8")

    # Extract KB (from split_idx-2 to include the horizontal rule if it's there)
    # Based on view, it's:
    # 192: ----
    # 193: 
    # 194: > Everything below...
    actual_start = split_idx
    if split_idx > 2 and "---" in lines[split_idx-2]:
        actual_start = split_idx - 2

    # Include the title for the new KB
    kb_header = "# CTF-Katana Knowledge Base\n\n> This is the legacy knowledge base extracted from the root README.\n\n"
    kb_content = kb_header + "".join(lines[actual_start:])
    kb_path.write_text(kb_content, encoding="utf-8")

    # Rewrite README without KB
    readme_content = "".join(lines[:actual_start])
    readme_path.write_text(readme_content, encoding="utf-8")

    print(f"Successfully moved KB to {kb_path}")
    print(f"README.md shortened to {len(lines[:actual_start])} lines")

if __name__ == "__main__":
    main()
