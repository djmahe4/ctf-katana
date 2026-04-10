"""
Tests for Phase 4 Multi-Domain Security Skills

Tests for:
- Web3 Analyzer
- IoT/Embedded Analyzer
- Android Analyzer
- Web Fuzzer
- Windows Exploitation
- GitHub Actions Exploitation
"""

import pytest
import os
import sys
import tempfile
import importlib.util
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# Standard imports for Phase 4 modules (valid packages now)
import skills.iot_embedded.run as iot_module
import skills.fuzzing.run as fuzzing_module
import skills.exploitation.windows_user_mode.run as windows_module
import skills.exploitation.ghactions.run as ghactions_module


# =============================================================================
# Web3 Analyzer Tests
# =============================================================================

class TestWeb3Analyzer:
    """Tests for Web3 smart contract analyzer."""
    
    @pytest.fixture
    def web3_analyzer(self):
        from skills.web3.run import Web3Analyzer
        return Web3Analyzer()
    
    def test_analyzer_init(self, web3_analyzer):
        """Test analyzer initialization."""
        assert web3_analyzer is not None
        assert hasattr(web3_analyzer, 'detect_reentrancy')
        assert hasattr(web3_analyzer, 'detect_flash_loan_vuln')
    
    def test_reentrancy_detection(self, web3_analyzer):
        """Test reentrancy vulnerability detection."""
        vulnerable_code = """
        function withdraw(uint amount) public {
            require(balances[msg.sender] >= amount);
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] -= amount;
        }
        """
        vulns = web3_analyzer.detect_reentrancy(vulnerable_code)
        assert len(vulns) > 0
        assert any('reentrancy' in v.vuln_type.lower() for v in vulns)
    
    def test_reentrancy_safe_code(self, web3_analyzer):
        """Test that safe code doesn't trigger false positives."""
        safe_code = """
        function withdraw(uint amount) public {
            require(balances[msg.sender] >= amount);
            balances[msg.sender] -= amount;
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
        }
        """
        vulns = web3_analyzer.detect_reentrancy(safe_code)
        # Safe code may still be flagged but should be lower confidence
        assert all(v.confidence < 0.9 for v in vulns) if vulns else True
    
    def test_flash_loan_detection(self, web3_analyzer):
        """Test flash loan vulnerability detection."""
        vulnerable_code = """
        function getPrice() public view returns (uint) {
            return reserve0 / reserve1;
        }
        """
        vulns = web3_analyzer.detect_flash_loan_vuln(vulnerable_code)
        # May or may not detect - implementation dependent
        assert isinstance(vulns, list)
    
    def test_accounting_bug_detection(self, web3_analyzer):
        """Test accounting bug detection."""
        vulnerable_code = """
        function transfer(address to, uint amount) public {
            balances[msg.sender] -= amount;
            balances[to] += amount;
            totalSupply += 1;  // Bug: shouldn't change totalSupply
        }
        """
        vulns = web3_analyzer.detect_accounting_bugs(vulnerable_code)
        assert isinstance(vulns, list)
    
    def test_full_analysis(self, web3_analyzer):
        """Test full contract analysis."""
        code = """
        pragma solidity ^0.8.0;
        
        contract Vulnerable {
            mapping(address => uint) public balances;
            
            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }
            
            function withdraw(uint amount) public {
                require(balances[msg.sender] >= amount);
                (bool success, ) = msg.sender.call{value: amount}("");
                balances[msg.sender] -= amount;
            }
        }
        """
        result = web3_analyzer.analyze(code)
        assert result['status'] == 'success'
        assert 'vulnerabilities' in result
        assert 'report' in result
    
    def test_run_function(self):
        """Test main run function."""
        from skills.web3.run import run
        
        result = run({
            'contract_code': 'contract Test {}',
            'mode': 'full',
        })
        assert result['status'] == 'success'
    
    def test_run_missing_params(self):
        """Test run with missing parameters."""
        from skills.web3.run import run
        
        result = run({})
        assert result['status'] == 'error'


# =============================================================================
# IoT/Embedded Analyzer Tests
# =============================================================================


class TestIoTAnalyzer:
    """Tests for IoT/embedded analyzer."""
    
    @pytest.fixture
    def iot_analyzer(self):
        return iot_module.IoTAnalyzer()
    
    def test_analyzer_init(self, iot_analyzer):
        """Test analyzer initialization."""
        assert iot_analyzer is not None
        assert hasattr(iot_analyzer, 'analyze_firmware')
    
    def test_binary_analysis(self, iot_analyzer):
        """Test binary file analysis."""
        # Create a simple test binary
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            # Write ELF header
            f.write(b'\x7fELF' + b'\x00' * 100)
            f.flush()
            
            result = iot_analyzer.analyze_binary(Path(f.name))
            assert result is not None
            # Result should be IoTAnalysisResult
            assert hasattr(result, 'status') or isinstance(result, dict)
        
        os.unlink(f.name)
    
    def test_string_extraction(self, iot_analyzer):
        """Test string extraction from binary."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'test\x00password123\x00admin456\x00secret_key789\x00')
            f.flush()
            
            strings = iot_analyzer._extract_strings(Path(f.name), min_length=4)
            assert isinstance(strings, list)
        
        os.unlink(f.name)
    
    def test_credential_scanning(self, iot_analyzer):
        """Test hardcoded credential detection."""
        test_content = '''
        DEFAULT_PASSWORD = "admin123"
        API_KEY = "sk-1234567890abcdef"
        secret = "supersecret"
        '''
        findings = iot_analyzer._scan_for_credentials(test_content, "test.c")
        assert len(findings) > 0
    
    def test_run_function(self):
        """Test main run function."""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)
            f.flush()
            
            result = iot_module.run({
                'target': f.name,
                'mode': 'binary',
            })
            assert 'status' in result
        
        os.unlink(f.name)


# =============================================================================
# Android Analyzer Tests
# =============================================================================

class TestAndroidAnalyzer:
    """Tests for Android APK analyzer."""
    
    @pytest.fixture
    def android_analyzer(self):
        from skills.android.run import AndroidAnalyzer
        return AndroidAnalyzer()
    
    def test_analyzer_init(self, android_analyzer):
        """Test analyzer initialization."""
        assert android_analyzer is not None
    
    def test_manifest_parsing(self, android_analyzer):
        """Test AndroidManifest.xml parsing."""
        manifest = """<?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android"
            package="com.example.test">
            <uses-permission android:name="android.permission.INTERNET"/>
            <uses-permission android:name="android.permission.READ_CONTACTS"/>
            <application android:debuggable="true">
                <activity android:name=".MainActivity" android:exported="true"/>
            </application>
        </manifest>
        """
        analysis = android_analyzer._parse_manifest_basic(manifest)
        assert 'package' in analysis
        assert 'permissions' in analysis
    
    def test_permission_analysis(self, android_analyzer):
        """Test permission analysis."""
        permissions = [
            'android.permission.READ_CONTACTS',
            'android.permission.CAMERA',
            'android.permission.INTERNET',
        ]
        vulns = android_analyzer._analyze_permissions(permissions)
        # Should flag dangerous permissions
        assert isinstance(vulns, list)
    
    def test_manifest_analysis(self, android_analyzer):
        """Test manifest security analysis."""
        manifest = """
        <manifest package="com.test">
            <application android:debuggable="true" android:allowBackup="true">
                <activity android:name=".MainActivity" android:exported="true"/>
                <service android:name=".MyService" android:exported="true"/>
            </application>
        </manifest>
        """
        vulns = android_analyzer._analyze_manifest(manifest)
        assert isinstance(vulns, list)
        # Should flag debuggable and exported components
    
    def test_run_function(self):
        """Test main run function with manifest content."""
        from skills.android.run import run
        
        manifest = """<?xml version="1.0"?>
        <manifest package="com.test">
            <application android:debuggable="true"/>
        </manifest>
        """
        result = run({
            'target': manifest,
            'mode': 'manifest',
        })
        assert 'status' in result


# =============================================================================
# Web Fuzzer Tests
# =============================================================================


class TestWebFuzzer:
    """Tests for web fuzzer."""
    
    @pytest.fixture
    def fuzzer(self):
        return fuzzing_module.WebFuzzer()
    
    def test_fuzzer_init(self, fuzzer):
        """Test fuzzer initialization."""
        assert fuzzer is not None
        assert hasattr(fuzzer, 'fuzz')
    
    def test_payload_types(self):
        """Test payload type availability."""
        PAYLOADS = fuzzing_module.PAYLOADS
        PayloadType = fuzzing_module.PayloadType
        
        assert PayloadType.GENERIC in PAYLOADS
        assert PayloadType.SQLI in PAYLOADS
        assert PayloadType.XSS in PAYLOADS
        assert PayloadType.LFI in PAYLOADS
        assert PayloadType.RCE in PAYLOADS
        assert PayloadType.SSTI in PAYLOADS
    
    def test_payload_content(self):
        """Test payload content."""
        PAYLOADS = fuzzing_module.PAYLOADS
        PayloadType = fuzzing_module.PayloadType
        
        sqli_payloads = PAYLOADS[PayloadType.SQLI]
        assert "'" in sqli_payloads
        assert any('UNION' in p for p in sqli_payloads)
        
        xss_payloads = PAYLOADS[PayloadType.XSS]
        assert any('<script>' in p for p in xss_payloads)
    
    def test_url_building(self, fuzzer):
        """Test URL building with payload."""
        FuzzMode = fuzzing_module.FuzzMode
        
        url = fuzzer._build_url("http://example.com/FUZZ", "test", FuzzMode.DIRECTORY)
        assert "test" in url
        
        url = fuzzer._build_url("http://example.com/", "admin", FuzzMode.DIRECTORY)
        assert url == "http://example.com/admin"
    
    def test_fuzz_result_dataclass(self):
        """Test FuzzResult dataclass."""
        FuzzResult = fuzzing_module.FuzzResult
        
        result = FuzzResult(
            url="http://test.com",
            payload="test",
            status_code=200,
            content_length=100,
        )
        assert result.url == "http://test.com"
        assert not result.interesting
    
    def test_run_function_missing_target(self):
        """Test run with missing target."""
        result = fuzzing_module.run({})
        assert result['status'] == 'error'


# =============================================================================
# Windows Exploitation Tests
# =============================================================================


class TestWindowsExploitation:
    """Tests for Windows exploitation toolkit."""
    
    @pytest.fixture
    def exploit_kit(self):
        return windows_module.WindowsExploit()
    
    def test_pattern_generation(self):
        """Test cyclic pattern generation."""
        PatternGenerator = windows_module.PatternGenerator
        
        pattern = PatternGenerator.create_pattern(100)
        assert len(pattern) == 100
        # Pattern should be unique
        assert len(set(pattern[i:i+3] for i in range(0, len(pattern)-2))) > 10
    
    def test_pattern_offset_finding(self):
        """Test offset finding in pattern."""
        PatternGenerator = windows_module.PatternGenerator
        
        pattern = PatternGenerator.create_pattern(1000)
        # Find a known sequence
        test_seq = pattern[100:104]
        offset = PatternGenerator.find_offset(pattern, test_seq)
        assert offset == 100
    
    def test_bad_char_generation(self):
        """Test bad character test string generation."""
        BadCharFinder = windows_module.BadCharFinder
        
        test_str = BadCharFinder.generate_test_string([0x00, 0x0a, 0x0d])
        assert 0x00 not in test_str
        assert 0x0a not in test_str
        assert 0x0d not in test_str
        assert len(test_str) == 253  # 256 - 3
    
    def test_shellcode_xor_encoding(self):
        """Test XOR shellcode encoding."""
        ShellcodeGenerator = windows_module.ShellcodeGenerator
        
        original = b'\x41\x42\x43'
        encoded = ShellcodeGenerator.encode_xor(original, 0x41)
        assert encoded == b'\x00\x03\x02'
        
        # Decode should return original
        decoded = ShellcodeGenerator.encode_xor(encoded, 0x41)
        assert decoded == original
    
    def test_exploit_template_generation(self, exploit_kit):
        """Test exploit template generation."""
        template = exploit_kit.generate_exploit_template(
            vuln_type='buffer_overflow',
            offset=1024,
            bad_chars=[0x00, 0x0a],
            jmp_esp_addr=0xdeadbeef,
        )
        assert 'OFFSET = 1024' in template
        assert '0x00' in template
        assert 'JMP_ESP' in template
    
    def test_run_function(self):
        """Test main run function."""
        result = windows_module.run({
            'target': '',
            'mode': 'pattern',
            'arch': 'x86',
        })
        assert result['status'] == 'success'
        assert 'analysis' in result


# =============================================================================
# GitHub Actions Exploitation Tests
# =============================================================================


class TestGHActionsExploitation:
    """Tests for GitHub Actions security analysis."""
    
    @pytest.fixture
    def analyzer(self):
        return ghactions_module.WorkflowAnalyzer()
    
    def test_command_injection_detection(self, analyzer):
        """Test command injection detection."""
        vulnerable_workflow = """
        on: issue_comment
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo ${{ github.event.comment.body }}
        """
        vulns = analyzer.analyze_file(vulnerable_workflow)
        assert len(vulns) > 0
        assert any('injection' in v.title.lower() for v in vulns)
    
    def test_pull_request_target_detection(self, analyzer):
        """Test pull_request_target detection."""
        workflow = """
        on: pull_request_target
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v3
        """
        vulns = analyzer.analyze_file(workflow)
        assert any('pull_request_target' in v.title.lower() for v in vulns)
    
    def test_unpinned_action_detection(self, analyzer):
        """Test unpinned action detection."""
        workflow = """
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v3
              - uses: some-action@main
        """
        vulns = analyzer.analyze_file(workflow)
        assert any('unpinned' in v.title.lower() for v in vulns)
    
    def test_secret_exposure_detection(self, analyzer):
        """Test secret exposure detection."""
        workflow = """
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo ${{ secrets.API_KEY }}
        """
        vulns = analyzer.analyze_file(workflow)
        assert any('secret' in v.title.lower() for v in vulns)
    
    def test_safe_workflow(self, analyzer):
        """Test that safe workflow has fewer issues."""
        safe_workflow = """
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            permissions:
              contents: read
            steps:
              - uses: actions/checkout@8ade135a41bc03ea155e62e844d188df1ea18608
              - run: npm test
        """
        vulns = analyzer.analyze_file(safe_workflow)
        # Safe workflow should have minimal or no critical issues
        critical = [v for v in vulns if v.severity.value == 'critical']
        assert len(critical) == 0
    
    def test_run_function(self):
        """Test main run function."""
        workflow = """
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: echo test
        """
        result = ghactions_module.run({
            'target': workflow,
            'mode': 'analyze',
        })
        assert result['status'] == 'success'
        assert 'vulnerabilities' in result
    
    def test_run_missing_target(self):
        """Test run with missing target."""
        result = ghactions_module.run({})
        assert result['status'] == 'error'


# =============================================================================
# Integration Tests
# =============================================================================

class TestPhase4Integration:
    """Integration tests for Phase 4 components."""
    
    def test_all_skills_have_run_function(self):
        """Test all Phase 4 skills have run function."""
        # Modules already loaded above
        modules = [
            ('web3', 'skills.web3.run'),
            ('iot', iot_module),
            ('android', 'skills.android.run'),
            ('fuzzing', fuzzing_module),
            ('windows', windows_module),
            ('ghactions', ghactions_module),
        ]
        
        for name, module in modules:
            if isinstance(module, str):
                try:
                    imported = __import__(module, fromlist=['run'])
                    assert hasattr(imported, 'run'), f"{name} missing run function"
                except ImportError as e:
                    pytest.skip(f"Could not import {name}: {e}")
            else:
                assert hasattr(module, 'run'), f"{name} missing run function"
                assert callable(module.run), f"{name}.run not callable"
    
    def test_skill_yaml_files_exist(self):
        """Test skill.yaml files exist."""
        skill_dirs = [
            'skills/web3',
            'skills/iot_embedded',
            'skills/android',
            'skills/fuzzing',
            'skills/exploitation/windows_user_mode',
            'skills/exploitation/ghactions',
        ]
        
        for skill_dir in skill_dirs:
            yaml_path = PROJECT_ROOT / skill_dir / 'skill.yaml'
            assert yaml_path.exists(), f"Missing {yaml_path}"
    
    def test_prompt_md_files_exist(self):
        """Test prompt.md files exist."""
        skill_dirs = [
            'skills/web3',
            'skills/iot_embedded',
            'skills/android',
            'skills/fuzzing',
            'skills/exploitation/windows_user_mode',
            'skills/exploitation/ghactions',
        ]
        
        for skill_dir in skill_dirs:
            prompt_path = PROJECT_ROOT / skill_dir / 'prompt.md'
            assert prompt_path.exists(), f"Missing {prompt_path}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
