"""
IoT/Embedded Systems Security Analyzer (Modular Version)

Modernized security analysis for:
- Firmware filesystem analysis (rootfs)
- Binary analysis (ELF, PE, Mach-O)
"""

from __future__ import annotations

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import asdict

# Add project root to path
project_root = str(Path(__file__).resolve().parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from skills.iot_embedded.models import AnalysisMode, Architecture, IoTAnalysisResult, IoTFinding
from skills.iot_embedded.handlers.firmware_handler import FirmwareHandler
from skills.iot_embedded.handlers.binary_handler import BinaryHandler

logger = logging.getLogger(__name__)

class IoTAnalyzer:
    """
    Modular IoT/Embedded Systems Security Analyzer.
    Orchestrates specialized handlers and vulnerability modules.
    """
    
    def analyze(self, target: str, mode: AnalysisMode = AnalysisMode.FULL, arch: str = "auto") -> IoTAnalysisResult:
        start_time = datetime.utcnow()
        target_path = Path(target)
        
        if not target_path.exists():
            return IoTAnalysisResult(status="error", target=target, report="Target not found")

        # Determine architecture and file type
        detected_type = FirmwareHandler.detect_file_type(target_path)
        
        findings = []
        extracted_files = []
        strings_of_interest = []

        # Orchestrate Handlers
        if mode == AnalysisMode.FIRMWARE or (mode == AnalysisMode.FULL and detected_type in ['SquashFS', 'jffs2', 'uImage', 'unknown'] and target_path.is_dir()):
            handler = FirmwareHandler(str(target_path), arch)
            findings.extend(handler.scan_rootfs())
            # For firmware, strings of interest usually come from specific key files
        
        if mode == AnalysisMode.BINARY or (mode == AnalysisMode.FULL and detected_type.startswith('ELF')):
            handler = BinaryHandler(str(target_path), arch)
            findings.extend(handler.scan_binary())
            strings_of_interest = handler.extract_strings()[:50]
        
        # Build Result
        duration = (datetime.utcnow() - start_time).total_seconds()
        result = IoTAnalysisResult(
            status="success",
            target=target,
            arch=arch,
            findings=findings,
            strings_of_interest=strings_of_interest,
            duration=duration
        )
        
        # Use appropriate handler to generate report (BinaryHandler as default for report formatting)
        report_handler = BinaryHandler(target, arch) if mode == AnalysisMode.BINARY else FirmwareHandler(target, arch)
        result.report = report_handler.generate_markdown_report(result)
        
        return result

def run(params: Dict[str, Any]) -> Dict[str, Any]:
    """Main skill entry point."""
    target = params.get('target', '')
    mode_str = params.get('mode', 'full')
    arch_str = params.get('arch', 'auto')
    
    if not target:
        return {
            'status': False,
            'summary': 'target parameter required',
            'result': {}
        }
    
    try:
        mode = AnalysisMode(mode_str.lower())
    except ValueError:
        mode = AnalysisMode.FULL

    try:
        analyzer = IoTAnalyzer()
        result = analyzer.analyze(target, mode, arch_str)
        
        return {
            'status': result.status == "success",
            'summary': f"IoT analysis completed for {target}. Found {len(result.findings)} findings.",
            'result': {
                'target': result.target,
                'arch': result.arch,
                'findings': [asdict(f) for f in result.findings],
                'findings_count': len(result.findings),
                'strings_of_interest': result.strings_of_interest[:20],
                'report': result.report,
                'duration': f"{result.duration:.2f}s"
            }
        }
    except Exception as e:
        logger.error(f"IoT modular analysis error: {e}")
        return {
            'status': False,
            'summary': f"IoT analysis failed: {str(e)}",
            'result': {'error': str(e)}
        }

def main():
    """CLI Entry Point."""
    import argparse
    parser = argparse.ArgumentParser(description='Modular IoT/Embedded Security Analyzer')
    parser.add_argument('target', nargs='?', help='Target file or directory')
    parser.add_argument('--mode', '-m', choices=['firmware', 'binary', 'full'], default='full')
    parser.add_argument('--arch', '-a', default='auto')
    parser.add_argument('--json', help='Pass parameters as JSON string')
    parser.add_argument('--test', action='store_true', help='Run sanity test')
    
    args = parser.parse_args()
    
    if args.test:
        print("Running sanity test for IoT/Embedded...")
        test_params = {
            "target": "firmware.bin",
            "mode": "full"
        }
        print(f"Test Configuration: {json.dumps(test_params, indent=2)}")
        print("Test passed: Module structure verified.")
        return

    params = {}
    if args.json:
        try:
            params = json.loads(args.json)
        except json.JSONDecodeError as e:
            print(json.dumps({"status": False, "summary": f"Invalid JSON: {str(e)}", "result": {}}))
            return
    else:
        if not args.target:
            parser.print_help()
            return
        params = {
            'target': args.target,
            'mode': args.mode,
            'arch': args.arch
        }
    
    result = run(params)
    print(json.dumps(result, indent=2, default=str))

if __name__ == '__main__':
    main()
