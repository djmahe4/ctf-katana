import os
import re
import logging
import asyncio
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from server.utils.research_rag import ResearchRAG
from skills.research_chrome_scraper.scraper import ChromeScraper, fetch_raw_json, fetch_raw_text
from skills.research_agent.git_miner import GitDiffParser

logger = logging.getLogger(__name__)

def _detect_lang_from_content(content: str) -> Optional[str]:
    """Lightweight regex to identify language hints in code snippets."""
    c = content.lower()
    if "pragma solidity" in c or "contract " in c: return "solidity"
    if "import java." in c or "public class " in c: return "java"
    if "<?php" in c: return "php"
    if "#include <" in c: return "c"
    if "def " in c and "import " in c: return "python"
    return None

class IntelligenceMiner:
    """
    Intelligence Miner for Phase 3.
    Extracts high-value code (exploits/patches) from high-value domains.
    """
    
    def __init__(self, rag: Optional[ResearchRAG] = None, workspace_root: Optional[str] = None):
        self.rag = rag or ResearchRAG(persist_directory=os.environ.get("KATANA_RAG_DIR", "data/research_db"))
        self.workspace_root = Path(workspace_root or os.getcwd())
        self.scraper = ChromeScraper(cache_path=str(self.workspace_root / "cve_cache.json"))
        self.diff_parser = GitDiffParser()
        
        # High value domains for exploit/patch code
        self.high_value_domains = [
            "github.com",
            "gitlab.com",
            "bitbucket.org",
            "gist.github.com",
            "security.snyk.io",
            "vuldb.com",
            "packetstormsecurity.com",
            "exploit-db.com",
            "advisories",
            "security-advisories",
            "djangoproject.com",
            "openwall.com",
            "nvd.nist.gov",
            "mitre.org"
        ]

    def _rank_urls(self, urls: List[str]) -> List[str]:
        """Ranks URLs by priority: Commits/PRs/Advisories > General > Releases (Noise)."""
        def score(url: str) -> int:
            u = url.lower()
            if any(p in u for p in ["/commit/", "/pull/", "/security/advisories/", "/gist."]):
                return 100
            if any(p in u for p in ["/issues/", "/vuln/", "/exploit/", "/poc/"]):
                return 80
            if any(p in u for p in ["/releases/tag/", "/tags/", "/archive/", "/download/"]):
                return -100 # Extreme deprioritization for noise
            return 0
            
        return sorted(urls, key=score, reverse=True)

    async def mine_cve(self, cve_id: str, github_link: str, max_depth: int = 1) -> Dict[str, Any]:
        """
        End-to-end mining: Fetch -> Discover -> Follow -> Extract -> Summarize.
        """
        logger.info(f"⛏️  Starting deep mining for {cve_id} (max_depth={max_depth})...")
        intelligence = []
        visited = {github_link}
        result = {
            "cve_id": cve_id,
            "intelligence_count": 0,
            "references_scraped": 0,
            "status": True,
            "is_grounded": False,
            "logic_hint": None
        }
        
        # 1. Fetch Raw CVE JSON from GitHub
        cve_data = fetch_raw_json(github_link)
        if not cve_data:
            return {"status": "error", "message": "Failed to fetch CVE JSON"}
            
        # 2. Extract References and Git Intelligence
        references = self._extract_references(cve_data)
        git_intelligence = self._extract_git_intelligence(cve_data)
        logger.info(f"Found {len(references)} references and {len(git_intelligence)} git targets for {cve_id}")

        # 3. Process Git Intelligence (Direct Patch Mining)
        for git_info in git_intelligence:
            repo_url = git_info.get("repo")
            program_files = git_info.get("programFiles", [])
            
            # Extract unique fix hashes from versions
            fix_hashes = []
            for v in git_info.get("versions", []):
                # Status 'affected' usually means the 'lessThan' version is the fix
                fh = v.get("lessThan") or v.get("lessThanOrEqual")
                if fh and len(fh) >= 7 and v.get("status") == "affected":
                    if fh not in fix_hashes:
                        fix_hashes.append(fh)
            
            if not fix_hashes:
                logger.info(f"No clear fix hashes found for {repo_url}")
                continue
                
            logger.info(f"🚀 Processing {len(fix_hashes)} potential fix commits for {repo_url}...")
            
            # Limit to top 5 unique hashes to avoid redundancy
            for fix_hash in fix_hashes[:5]:
                patch_url = self.diff_parser.get_patch_url(repo_url, fix_hash)
                if not patch_url:
                    continue
                    
                logger.info(f"🚀 Fetching and observing patch from {patch_url}")
                try:
                    # Use fetch_raw_text for patch files (they are not JSON)
                    patch_content = fetch_raw_text(patch_url) if "patch" in patch_url else None
                    if not patch_content:
                        # Fallback to standard scraper
                        async with self.scraper as s:
                            p_info = await s.fetch_advisory(patch_url)
                            patch_content = p_info.get("description", "")
                    
                    if patch_content and "---" in patch_content:
                        # Parse and filter for the specific program files
                        file_diffs = self.diff_parser.parse_patch(patch_content, filter_files=program_files)
                        
                        if file_diffs:
                            logger.info(f"🔍 Observed {len(file_diffs)} relevant file changes in patch ({fix_hash})")
                            analysis = self.diff_parser.analyze_logic_change(file_diffs)
                            
                            # Store the targeted intelligence
                            targeted_content = f"--- PATCH ANALYSIS ---\n{analysis}\n\n--- FILTERED DIFF ---\n"
                            targeted_content += "\n".join(file_diffs.values())
                            
                            self.rag.add_document(
                                content=targeted_content,
                                source="git_diff_observer",
                                source_type="git_patch",
                                title=f"Targeted Git Patch for {cve_id} ({fix_hash})",
                                url=patch_url,
                                metadata={
                                    "cve_id": cve_id,
                                    "purpose": "patch",
                                    "is_git_diff": True,
                                    "repo": repo_url,
                                    "commit": fix_hash,
                                    "affected_files": list(file_diffs.keys()),
                                    "observation_summary": analysis
                                }
                            )
                            intelligence.append({"url": patch_url, "type": "patch", "content": targeted_content})
                            
                            # Mark as grounded for initial results
                            if not result.get("is_grounded"):
                                result["is_grounded"] = True
                                result["logic_hint"] = analysis
                except Exception as e:
                    logger.warning(f"Failed to observe patch {fix_hash}: {e}")

        # 4. Filter and Rank High-Value URLs from references
        hv_urls = [url for url in references if any(domain in url.lower() for domain in self.high_value_domains)]
        hv_urls = self._rank_urls(hv_urls)
        logger.info(f"Ranked high-value matches: {len(hv_urls)}")
        
        # 4. Scrape URLs for Code Blocks
        async with self.scraper as s:
            for url in hv_urls[:7]: # Increased limit to 7 for better coverage
                if url in visited: continue
                visited.add(url)
                
                content = await s.fetch_advisory(url)
                if "error" in content:
                    continue
                
                description = content.get("description", "")
                if not description: continue

                logger.info(f"📊 Scraped {len(description)} chars and {len(content.get('snippets', []))} snippets from {url}")
                
                # Store full description in RAG
                self.rag.add_document(
                    content=description,
                    source="intelligence_miner",
                    source_type="cve_advisory",
                    title=content.get("title", ""),
                    url=url,
                    metadata={
                        "cve_id": cve_id, 
                        "scraped_at": content.get("scraped_at", ""),
                        "type": "full_page"
                    }
                )
                
                # Process and store structured snippets
                for snippet in content.get("snippets", []):
                    # Combine context and code for RAG
                    full_snippet = f"--- CONTEXT ---\n{snippet['context']}\n--- CODE ---\n{snippet['code']}"
                    
                    # Extract extension hint from URL if possible
                    ext_hint = os.path.splitext(url.split('?')[0])[1].lower() if '.' in url else ""
                    lang_hint = _detect_lang_from_content(snippet['code'])
                    
                    self.rag.add_document(
                        content=full_snippet,
                        source="intelligence_miner",
                        source_type="cve_snippet",
                        title=f"{snippet['purpose'].upper()} snippet from {content.get('title', '')}",
                        url=url,
                        metadata={
                            "cve_id": cve_id,
                            "purpose": snippet["purpose"],
                            "type": "snippet",
                            "scraped_at": content.get("scraped_at", ""),
                            "source_extension": ext_hint,
                            "language_hint": lang_hint
                        }
                    )
                    intelligence.append({
                        "url": url, 
                        "type": snippet["purpose"], 
                        "content": snippet["code"],
                        "source_extension": ext_hint,
                        "language_hint": lang_hint
                    })
                
                # 4.2 Recursive Link Discovery
                # Use regex to find potential commit/pull references in the text
                secondary_urls = re.findall(r'https?://(?:gist\.)?github\.com/[\w-]+/[\w-]+/(?:commit|pull|[\w-]+)/\w+', description)
                # Prioritize 'exploit' or 'poc' mentioned URLs in text if any
                text_links = re.findall(r'https?://[^\s)\]]+', description)
                for link in text_links:
                    link_lower = link.lower()
                    if any(kw in link_lower for kw in ['exploit', 'poc', 'vuln', 'patch']):
                        if any(dom in link_lower for dom in self.high_value_domains):
                            secondary_urls.append(link)

                for s_url in list(set(secondary_urls))[:5]: # Limit secondary follow
                    if s_url not in visited:
                        visited.add(s_url)
                        raw_url = s_url
                        # If it's a GitHub commit/pull, we might prefer the .patch view for raw code
                        if ("/commit/" in s_url or "/pull/" in s_url) and not s_url.endswith(".patch"):
                            raw_url = f"{s_url.rstrip('/')}.patch"
                        
                        logger.info(f"DEBUG: Following secondary high-value URL: {raw_url}")
                        s_content = await s.fetch_advisory(raw_url)
                        if "description" in s_content and len(s_content["description"]) > 100:
                            self.rag.add_document(
                                content=s_content["description"],
                                source="intelligence_miner",
                                source_type="cve_secondary",
                                title=s_content.get("title", ""),
                                url=raw_url,
                                metadata={"cve_id": cve_id, "type": "secondary", "parent_url": url}
                            )
                            # Extract code from patch/secondary text
                            s_snippets = self._extract_code_snippets(s_content["description"])
                            for snippet in s_snippets:
                                intelligence.append({"url": raw_url, "type": "patch", "content": snippet})
                    
        result["intelligence_count"] = len(intelligence)
        result["references_scraped"] = len(hv_urls[:7])
        return result

    def _extract_references(self, cve_data: Dict[str, Any]) -> List[str]:
        """Extracts URLs from CVE JSON structure."""
        urls = []
        try:
            refs = cve_data.get("containers", {}).get("cna", {}).get("references", [])
            for ref in refs:
                url = ref.get("url")
                if url:
                    urls.append(url)
        except Exception as e:
            logger.error(f"Error extracting references: {e}")
        return urls

    def _extract_git_intelligence(self, cve_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extracts git repo and version info from 'affected' section."""
        git_intel = []
        try:
            affected_list = cve_data.get("containers", {}).get("cna", {}).get("affected", [])
            for affected in affected_list:
                repo = affected.get("repo")
                if repo and ("git" in repo.lower() or "github" in repo.lower() or "gitlab" in repo.lower()):
                    git_intel.append({
                        "repo": repo,
                        "product": affected.get("product"),
                        "programFiles": affected.get("programFiles", []),
                        "versions": affected.get("versions", [])
                    })
        except Exception as e:
            logger.error(f"Error extracting git intelligence: {e}")
        return git_intel

    def _extract_code_snippets(self, text: str) -> List[str]:
        """
        Extracts code snippets using heuristics.
        Handles both markdown blocks and plain text patterns.
        """
        snippets = []
        
        # 1. Markdown code blocks (if preserved)
        blocks = re.findall(r'```(?:[\w+-]+)?\n(.*?)\n```', text, re.DOTALL)
        if blocks:
            logger.info(f"🔍 Found {len(blocks)} markdown code blocks")
            snippets.extend(blocks)
            
        # 2. Diff / Patch patterns (common in advisories)
        diff_pattern = r'((?:--- .*\n\+\+\+ .*\n(?:@@ .*\n)?(?:[ +-].*\n)+))'
        diffs = re.findall(diff_pattern, text)
        if diffs:
            logger.info(f"🔍 Found {len(diffs)} diff/patch snippets")
            snippets.extend(diffs)
            
        # 3. C/Python/JS function-like patterns (fallback)
        if not snippets:
            # Look for common function definitions if no obvious blocks
            func_pattern = r'(?:def|func|function|void|static)\s+\w+\s*\(.*?\)\s*\{'
            funcs = re.findall(func_pattern, text)
            if funcs:
                logger.info(f"🔍 Found {len(funcs)} potential function start patterns")
        
        return [s.strip() for s in snippets if len(s.strip()) > 20]

    def verify_purple_loop(self, cve_id: str) -> bool:
        """
        Checks if RAG has enough intelligence for Purple Loop Gate.
        """
        search_results = self.rag.search(f"exploit PoC or security patch for {cve_id}", limit=10)
        
        has_exploit = False
        has_patch = False
        
        for i, res in enumerate(search_results):
            logger.info(f"Result {i+1} Title: {res.title}")
            logger.info(f"Result {i+1} Snippet: {res.content[:100]}...")
            content = res.content.lower()
            if "exploit" in content or "poc" in content or "vuln" in content:
                has_exploit = True
            if "patch" in content or "fix" in content or "hardened" in content:
                has_patch = True
                
        return has_exploit and has_patch
