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
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import required skills/utils
from server.utils.knowledge_registry import KnowledgeRegistry
from skills.research_challenge_gen.run import run as run_gen
from skills.flagger.run import run as run_flagger
from skills.ctfd_setup.run import run as run_setup
from skills.research_agent.intelligence_miner import IntelligenceMiner

logger = logging.getLogger(__name__)

async def async_input(prompt: str) -> str:
    """Non-blocking input wrapper."""
    return await asyncio.get_event_loop().run_in_executor(None, input, prompt)

async def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Execute the Purple Loop Orchestration.
    
    Args:
        params: 
            - target: CVE-ID or URL
            - difficulty: medium
            - ai_hardening: standard
            - interactive: bool (Human-In-The-Loop)
    """
    target = params.get('target')
    difficulty = params.get('difficulty', 'medium')
    ai_hardening = params.get('ai_hardening', 'standard')
    interactive = params.get('interactive', False)
    
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
        gen_params = {
            'finding': {
                'id': target,
                'vuln_type': research_result.get('intent', 'web'),
                'title': f"Challenge for {target}",
                'description': pl.get('patch_analysis', 'Exploit the vulnerability.')
            },
            'difficulty': difficulty,
            'ai_hardening': ai_hardening,
            'logic_delta': pl.get('logic_delta'),
            'intelligence_snippets': pl.get('intelligence_snippets')
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
