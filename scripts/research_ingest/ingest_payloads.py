import os
import json
import tempfile
import subprocess
import shutil
import re
from pathlib import Path

# Optional markdown parsing (we rely on simple text extraction if markdown module is missing)
try:
    import markdown
except ImportError:
    markdown = None

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

def parse_markdown_simple(content):
    """Fallback simple parser if markdown library is unavailable."""
    headings = []
    paragraphs = []
    for line in content.splitlines():
        line = line.strip()
        if line.startswith('#'):
            headings.append(line.lstrip('# ').strip())
        elif line and not line.startswith('`') and not line.startswith('>'):
            paragraphs.append(line)
    return headings, paragraphs

def ingest_payloads_all_the_things(repo_url):
    """
    Ingests PayloadsAllTheThings repository into a JSON knowledge base.
    Uses a temporary directory to avoid git submodules and namespace pollution.
    """
    knowledge_base = []
    
    with tempfile.TemporaryDirectory() as temp_dir:
        clone_repo(repo_url, temp_dir)
        
        # PayloadsAllTheThings structure has categories as top-level directories
        for root, dirs, files in os.walk(temp_dir):
            # Skip hidden git folders
            if '.git' in root:
                continue
                
            for file in files:
                if file.lower().endswith(".md"):
                    file_path = os.path.join(root, file)
                    category = os.path.basename(os.path.dirname(file_path))
                    
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            markdown_content = f.read()
                            
                            # Simple extraction for RAG chunking
                            headings, paragraphs = parse_markdown_simple(markdown_content)
                            
                            # We only care about files with substantial content
                            if len(headings) > 0 or len(paragraphs) > 5:
                                knowledge_base.append({
                                    "source": "PayloadsAllTheThings",
                                    "category": category,
                                    "topic": file.replace('.md', ''),
                                    "headings": headings[:10], # Limit size per chunk
                                    "summary": " ".join(paragraphs[:5]), # First few paragraphs as summary
                                    "full_text_hash": hash(markdown_content) # for deduplication
                                })
                    except Exception as e:
                        print(f"[!] Error reading {file_path}: {e}")

    return knowledge_base

if __name__ == "__main__":
    repo_url = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    output_file = os.path.join(os.path.dirname(__file__), "..", "..", "data", "payloads_index.json")
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    print("[*] Starting PayloadsAllTheThings ingestion...")
    kb = ingest_payloads_all_the_things(repo_url)
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(kb, f, indent=4)
        
    print(f"[+] Ingestion complete! Extracted {len(kb)} knowledge chunks.")
    print(f"[+] Saved to: {output_file}")
