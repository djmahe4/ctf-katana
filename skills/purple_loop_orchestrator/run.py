"""
Purple Engine - Purple Loop Orchestrator (The Conductor)

Automates the end-to-end vulnerability-to-challenge pipeline.
Sequence: Research -> Scaffolding -> Hardening/Flagger -> Deployment.
"""

import os
import sys
import json
import logging
import asyncio
import argparse
from pathlib import Path
from typing import Dict, Any, List

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import required skills/utils
from server.utils.knowledge_registry import KnowledgeRegistry
from skills.research_challenge_gen.run import run as run_gen
from skills.flagger.run import run as run_flagger
from skills.ctfd_setup.run import run as run_setup
from skills.research_agent.intelligence_miner import IntelligenceMiner

logger = logging.getLogger(__name__)

def _detect_category(target: str, pl: Dict[str, Any], hint: str = None) -> str:
    """Detection logic to classify the technology stack (Web, IoT, Web3)."""
    if hint and hint.lower() in ["web", "iot", "blockchain", "pwn"]:
        logger.info(f"Using provided category hint: {hint}")
        return hint.lower()

    # Build a massive text blob from all available research metadata
    text_data = [
        target,
        str(pl.get('logic_analysis', '')),
        str(pl.get('patch_analysis', '')),
        str(pl.get('summary', '')),
        " ".join([s.get('content', '') for s in pl.get('intelligence_snippets', [])]),
        " ".join([s.get('source', '') or "" for s in pl.get('intelligence_snippets', [])]),
        " ".join(pl.get('keywords', []))
    ]
    text_blob = " ".join(text_data).lower()
    
    logger.debug(f"Category detection blob length: {len(text_blob)}")

    # Web3 / Blockchain - High Priority
    blockchain_keywords = ['vyper', 'solidity', 'smart contract', 'blockchain', 'ethereum', 'web3', 'evm', 'on-chain', 'defi', 'dex', 'mint', 'burn']
    if any(k in text_blob for k in blockchain_keywords):
        return "blockchain"
        
    # IoT / Embedded / Binary
    iot_keywords = ['iot', 'embedded', 'firmware', 'buffer overflow', 'overflow', 'memory corruption', 'binary', 'openvpn', 'rtos', 'esp32', 'pwn', 'assembly', 'heap exploitation', 'stack smashing', 'arm', 'mips', 'risc-v']
    if any(k in text_blob for k in iot_keywords):
        return "iot"

    # Default to Web
    return "web"

async def async_input(prompt: str) -> str:
    """Non-blocking input wrapper."""
    return await asyncio.get_event_loop().run_in_executor(None, input, prompt)

def _export_challenge(challenge: Dict[str, Any], target_id: str) -> str:
    """
    Exports the generated challenge files to disk in an isolated directory.
    Format: generated_challenges/{timestamp}_{category}_{target_id}/
    """
    import shutil
    from datetime import datetime
    
    # 1. Prepare directory name
    timestamp = datetime.now().strftime("%H%M%S") # Just time since date is often redundant in session
    category = challenge.get('category', 'misc')
    vuln_type = challenge.get('vuln_type', 'unknown')
    
    # Sanitize category/vuln_type/target_id for safe directory naming
    safe_target = "".join(c if c.isalnum() or c in "-_" else "_" for c in target_id)
    safe_vuln = "".join(c if c.isalnum() or c in "-_" else "_" for c in vuln_type.lower())
    
    # Directory format: generated_challenges/{category}_{safe_vuln}_{timestamp}_{safe_target}/
    dir_name = f"{category}_{safe_vuln}_{timestamp}_{safe_target}"
    export_path = PROJECT_ROOT / "generated_challenges" / dir_name
    
    export_path.mkdir(parents=True, exist_ok=True)
    
    # 2. Write synthesized source files
    generated_files = challenge.get('generated_files', [])
    for gf in generated_files:
        filename = gf.get('name', 'app.py')
        # Simple sanitization
        filename = "".join(c if c.isalnum() or c in "._-" else "_" for c in filename)
        file_path = export_path / filename
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(gf.get('content', ''))
            
    # 2.5 Migrate Browser Snapshots for Auditability
    # Snapshots are usually captured by ChromeScraper during the mining phase
    snapshot_dir = PROJECT_ROOT / "snapshots"
    if snapshot_dir.exists():
        target_snapshots = export_path / "research_snapshots"
        target_snapshots.mkdir(exist_ok=True)
        for snap in snapshot_dir.glob(f"*{target_id}*"):
            shutil.copy2(snap, target_snapshots / snap.name)
            logger.info(f"✅ Audited snapshot copied: {snap.name}")
            
    # 3. Generate and write manifest.json
    manifest = {
        "challenge_id": challenge.get("id"),
        "name": challenge.get("name"),
        "category": category,
        "difficulty": challenge.get("difficulty"),
        "points": challenge.get("points"),
        "description": challenge.get("description"),
        "flag": challenge.get("flag"),
        "hints": challenge.get("hints"),
        "solution": challenge.get("solution"),
        "source_finding": challenge.get("source_finding"),
        "created_at": challenge.get("created_at"),
        "files_exported": [f['name'] for f in generated_files]
    }
    
    with open(export_path / "challenge_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        
    return str(export_path)

async def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute the Purple Loop Orchestration.
    
    Args:
        params: 
            - target: CVE-ID or URL
            - difficulty: medium
            - ai_hardening: standard
            - interactive: bool (Human-In-The-Loop)
            - category_hint: optional string
    """
    target = params.get('target')
    difficulty = params.get('difficulty', 'medium')
    ai_hardening = params.get('ai_hardening', 'standard')
    interactive = params.get('interactive', False)
    category_hint = params.get('category_hint')
    
    steps_completed = []
    
    try:
        # 1. Research Phase
        registry = KnowledgeRegistry(workspace_root=PROJECT_ROOT)
        registry.ensure_bootstrapped()
        
        logger.info(f"{' [HITL] ' if interactive else ''}🔍 Starting Research for: {target}")
        research_result = await registry.query(target)
        
        if not research_result.get('purple_loop', {}).get('has_fix'):
            if target.startswith("CVE-"):
                logger.info(f"⚡ Cache Miss! Triggering IntelligenceMiner for {target}...")
                
                # We need the githubLink for extraction. 
                # For now, we construct it based on the CVE-ID patterns used by CVEProject.
                # Format: https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/1xxx/CVE-2024-1234.json
                # Actually, the Miner's fetch_raw_json handles github links.
                year = target.split("-")[1]
                id_num = target.split("-")[2]
                folder = id_num[:-3] + "xxx" if len(id_num) > 3 else "0xxx"
                gh_link = f"https://github.com/CVEProject/cvelistV5/blob/main/cves/{year}/{folder}/{target}.json"
                
                miner = IntelligenceMiner(rag=registry.rag, workspace_root=str(PROJECT_ROOT))
                mine_result = await miner.mine_cve(target, gh_link)
                
                if mine_result.get("status") == "success":
                    logger.info("✅ Mining complete. Re-querying registry...")
                    research_result = await registry.query(target)
                else:
                    logger.warning(f"❌ Mining failed: {mine_result.get('message')}")
            
            if not research_result.get('purple_loop', {}).get('has_fix'):
                logger.warning(f"❌ No verified fix found for {target} even after mining.")
                return {
                    'status': 'error',
                    'message': f"Insufficient intelligence found for {target}. Cannot automate Purple Loop.",
                    'steps_completed': steps_completed
                }
        
        pl = research_result['purple_loop']
        logger.info(f"✅ Research success: Found fix at {pl.get('fix_file')}:{pl.get('fix_line')}")
        
        if interactive:
            print("\n" + "="*50)
            print(f"RESEARCH RESULTS FOR {target}:")
            print(f"Vulnerable Sink: {pl.get('vuln_sink')}")
            print(f"Verified Fix File: {pl.get('fix_file')}")
            print(f"Verified Fix Line: {pl.get('fix_line')}")
            print("="*50)
            choice = await async_input("Proceed to Scaffolding phase? [Y/n]: ")
            if choice.lower() == 'n':
                return {'status': 'cancelled', 'message': 'User cancelled after research.', 'steps_completed': steps_completed}

        steps_completed.append("Research Complete")
        
        # 2. Challenge Scaffolding Phase
        logger.info("🏗️  Scaffolding Challenge via research_challenge_gen...")
        
        # Enhanced Category Detection
        category = _detect_category(target, pl, category_hint)
        logger.info(f"📊 Detected challenge category: {category}")
        
        gen_params = {
            'finding': {
                'id': target,
                'vuln_type': category,
                'title': f"Challenge for {target}",
                'description': pl.get('patch_analysis', 'Exploit the vulnerability.')
            },
            'difficulty': difficulty,
            'ai_hardening': ai_hardening,
            'logic_delta': pl.get('logic_delta'),
            'intelligence_snippets': pl.get('intelligence_snippets'),
            'category': category
        }
        
        gen_result = run_gen(gen_params)
        if gen_result.get('status') != 'success':
            return {
                'status': 'error',
                'message': f"Challenge generation failed: {gen_result.get('message')}",
                'steps_completed': steps_completed
            }
        
        challenge = gen_result['challenge']
        logger.info(f"✅ Scaffolding complete: Created challenge {challenge['id']} at {challenge.get('path', 'unknown')}")

        if interactive:
            print("\n" + "="*50)
            print(f"SCAFFOLDING RESULTS:")
            print(f"Challenge ID: {challenge['id']}")
            print(f"Source Path: {challenge.get('path')}")
            print("="*50)
            choice = await async_input("Proceed to Flag Hardening phase? [Y/n]: ")
            if choice.lower() == 'n':
                return {'status': 'cancelled', 'message': 'User cancelled after scaffolding.', 'steps_completed': steps_completed, 'challenge_id': challenge['id']}

        steps_completed.append("Scaffolding Complete")
        
        # 2.5 Disk Export Phase (New Integration)
        logger.info(f"💾 Exporting challenge to disk...")
        export_path = _export_challenge(challenge, target)
        challenge['export_path'] = export_path
        logger.info(f"✅ Export complete: Files saved to {export_path}")
        steps_completed.append("Disk Export Complete")
        
        # 3. Flagger (Hiding the Flag) Phase
        logger.info("🚩 Hardening Flag via Flagger...")
        flagger_params = {
            'flag': challenge.get('flag', 'flag{fake_flag}'),
            'level': 'moderate',
            'handler': 'web' if challenge.get('category') == 'web' else 'reverse',
            'template': 'python'
        }
        flagger_result = run_flagger(flagger_params)
        if flagger_result.get('status') == 'success':
            steps_completed.append("Flag Hardening Complete")
            challenge['hardened_flag_payload'] = flagger_result.get('payload')
        else:
            logger.warning(f"⚠️ Flagger failed: {flagger_result.get('message')}. Proceeding with raw flag.")

        # 4. Deployment Phase
        logger.info("🚀 Preparing CTFd Deployment...")
        setup_params = {
            'challenge': challenge,
            'dry_run': True # Use dry_run for now since we don't have CTFd creds in env
        }
        setup_result = run_setup(setup_params)
        if setup_result.get('status') == 'success':
            steps_completed.append("CTFd Setup Prepared")
        else:
            logger.warning(f"⚠️ CTFd Setup failed: {setup_result.get('message')}")
        
        return {
            'status': 'success',
            'challenge_id': challenge['id'],
            'export_path': export_path,
            'steps_completed': steps_completed,
            'message': f"Purple Loop completed for {target}. Challenge generated and ready for deployment."
        }
        
    except Exception as e:
        logger.error(f"Orchestration error: {e}", exc_info=True)
        return {
            'status': 'error',
            'error': str(e),
            'steps_completed': steps_completed
        }

async def main():
    parser = argparse.ArgumentParser(description="Purple Engine - Purple Loop Orchestrator")
    parser.add_argument("--target", required=True, help="Target CVE-ID or URL")
    parser.add_argument("--difficulty", default="medium", choices=["easy", "medium", "hard"], help="Challenge difficulty")
    parser.add_argument("--interactive", "-i", action="store_true", help="Enable Human-In-The-Loop interactive mode")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    params = {
        'target': args.target,
        'difficulty': args.difficulty,
        'interactive': args.interactive
    }
    
    result = await run(params)
    print("\n" + "="*50)
    print("FINAL ORCHESTRATION RESULT:")
    print(json.dumps(result, indent=2))
    print("="*50)

if __name__ == "__main__":
    asyncio.run(main())
