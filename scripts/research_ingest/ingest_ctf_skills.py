import os
import json
import tempfile
import subprocess
from pathlib import Path

def clone_repo(repo_url, target_dir):
    print(f"[*] Shallow cloning {repo_url} into {target_dir}...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, target_dir],
            check=True,
            capture_output=True,
            text=True
        )
        print("[+] Clone successful.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Clone failed: {e.stderr}")
        raise

def parse_skill_md(content):
    """Simple parser to extract intent and strategy from SKILL.md."""
    headings = []
    paragraphs = []
    
    lines = content.splitlines()
    in_frontmatter = False
    frontmatter = []
    
    for line in lines:
        stripped = line.strip()
        # Extract YAML frontmatter
        if stripped == "---":
            in_frontmatter = not in_frontmatter
            continue
            
        if in_frontmatter:
            frontmatter.append(stripped)
        elif stripped.startswith('#'):
            headings.append(stripped.lstrip('# ').strip())
        elif stripped and not stripped.startswith('`') and not stripped.startswith('>'):
            paragraphs.append(stripped)
            
    return frontmatter, headings, paragraphs

def ingest_ctf_skills(repo_url):
    """
    Ingests ljagiello/ctf-skills repository into a JSON knowledge base.
    Uses 'Option A' strategy from the prompt: parsing SKILL.md without code duplication.
    """
    knowledge_base = []
    
    with tempfile.TemporaryDirectory() as temp_dir:
        clone_repo(repo_url, temp_dir)
        
        # Walk and look specifically for SKILL.md files
        for root, dirs, files in os.walk(temp_dir):
            if "SKILL.md" in files:
                file_path = os.path.join(root, "SKILL.md")
                skill_category = os.path.basename(root)
                
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()
                        frontmatter, headings, paragraphs = parse_skill_md(content)
                        
                        knowledge_base.append({
                            "source": "ctf-skills",
                            "folder": skill_category,
                            "intent_data": frontmatter,
                            "key_headings": headings[:10],
                            "strategy_summary": " ".join(paragraphs[:5])
                        })
                except Exception as e:
                    print(f"[!] Error reading {file_path}: {e}")

    return knowledge_base

if __name__ == "__main__":
    repo_url = "https://github.com/ljagiello/ctf-skills.git"
    output_file = os.path.join(os.path.dirname(__file__), "..", "..", "data", "external_skills_index.json")
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    print("[*] Starting ljagiello/ctf-skills ingestion...")
    kb = ingest_ctf_skills(repo_url)
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(kb, f, indent=4)
        
    print(f"[+] Ingestion complete! Extracted {len(kb)} external skill definitions.")
    print(f"[+] Saved to: {output_file}")
