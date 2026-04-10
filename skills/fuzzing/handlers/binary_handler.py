import logging
import subprocess
from typing import Dict, Any, List
from pathlib import Path

from skills.fuzzing.models import FuzzRunResult, FuzzCategory, FuzzFinding, FuzzerSeverity
from skills.fuzzing.base import FuzzerHandlerBase

logger = logging.getLogger(__name__)

class BinaryHandler(FuzzerHandlerBase):
    """Handler for ELF/PE binary analysis and harness generation."""

    def analyze(self, target: str, **kwargs) -> FuzzRunResult:
        result = self.create_empty_result(FuzzCategory.BINARY, target)
        target_path = Path(target)

        if not target_path.exists():
            return result

        # Basic analysis (mimicking 'checksec' and string search)
        findings = self._perform_static_analysis(target_path)
        result.findings.extend(findings)

        # Harness generation thinking
        harness_type = kwargs.get('harness', 'libfuzzer')
        harness_code = self._generate_harness_template(target_path, harness_type)
        
        if harness_code:
            harness_path = target_path.with_suffix(f'.{harness_type}_harness.cpp')
            try:
                with open(harness_path, 'w') as f:
                    f.write(harness_code)
                result.artifacts.append(str(harness_path))
                result.summary += f" [Harness Generated: {harness_path.name}]"
            except Exception as e:
                logger.error(f"Failed to write harness: {e}")

        result.statistics = {"findings_count": len(result.findings), "artifacts_count": len(result.artifacts)}
        return result

    def _perform_static_analysis(self, target_path: Path) -> List[FuzzFinding]:
        findings = []
        try:
            # Check for common vulnerable functions
            unsafe_funcs = ["gets", "strcpy", "sprintf", "scanf"]
            # Simplified 'strings' like check
            with open(target_path, 'rb') as f:
                content = f.read()
                
            for func in unsafe_funcs:
                if func.encode() in content:
                    findings.append(FuzzFinding(
                        vulnerability_id="potential_unsafe_func",
                        description=f"Potential unsafe function '{func}' found in binary.",
                        severity=FuzzerSeverity.MEDIUM,
                        payload="N/A",
                        evidence=f"String residue of '{func}' detected.",
                        metadata={"function": func}
                    ))
        except Exception as e:
            logger.debug(f"Static analysis error: {e}")
        
        return findings

    def _generate_harness_template(self, target_path: Path, harness_type: str) -> str:
        """Drafts a fuzzer harness based on common patterns."""
        if harness_type == 'libfuzzer':
            return f"""
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// TODO: Link with target binary or object file
extern "C" int target_function(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {{
    if (Size < 1) return 0;
    
    // Call the vulnerable target function
    target_function(Data, Size);
    
    return 0;
}}
"""
        elif harness_type == 'afl':
            return f"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Compile with afl-clang-fast or afl-gcc
int main(int argc, char **argv) {{
    unsigned char buf[1024];
    while (__AFL_LOOP(1000)) {{
        ssize_t n = read(0, buf, sizeof(buf));
        if (n > 0) {{
            // TODO: Call target entry point with buf
        }}
    }}
    return 0;
}}
"""
        return ""
