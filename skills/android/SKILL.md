---
name: android-analyzer
description: Android Application Security Analyzer. Use for static and dynamic analysis of APKs, Frida instrumentation, and identifying mobile-specific vulnerabilities (Intent redirection, data leakage).
risk: moderate
source: local
---

# Android Security Analyzer

This skill provides comprehensive dissection of Android applications, ensuring the identification of deep vulnerabilities across both the application and the underlying OS layers.

## Core Triggers

- `APK_Security_Audit`: General analysis of a provided `.apk` file or package name.
- `Frida_Instrumentation`: Creating and injecting hooks for API monitoring or bypasses.
- `Manifest_Inspection`: Targeted analysis of `AndroidManifest.xml` for permissions and exported components.
- `Dynamic_Instrumentation`: Real-time monitoring of app behavior (UI, file system, network).
- `Inter_Component_Communication_Attack`: Verification of intent-redirection and activity-hijacking.

## Mandatory Context

- `APK_Path`: Location of the target application.
- `Analysis_Mode`: (`static`, `dynamic`, `frida`, `manifest`, `full`).
- `Android_API_Level`: Target API level (e.g., 30 for Android 11).
- `Root_Access`: Whether the analysis environment is rooted.
- `Package_Name`: (Required for on-device/dynamic analysis).

## Orchestration Workflow

1. **Decompilation**: Use Apktool/Jadx via `android/run.py` to extract source and resources.
2. **Static Review**: Analyze the Manifest and Smali/Java code for insecure storage and hardcoded secrets.
3. **Dynamic Set-up**: Configure the ADB environment and start Frida-Server if dynamic analysis is requested.
4. **Instrumentation**: Define and execute Frida scripts to hook critical methods (e.g., SSL Pinning bypass, root detection).
5. **Vulnerability Synthesis**: Link findings like sensitive data leakage to exploitable IPC mechanisms.

## When to Use

- When auditing Android mobile applications for security flaws.
- When generating Android-themed CTF challenges for the Purple Engine.
- For dynamic analysis of suspicious or unknown APKs.

## When NOT to Use

- For iOS app analysis (unless specifically requested/compatible).
- For general backend web security (use the Vuln Discovery or Web skills).

## Strategy: Sophisticated Research

> [!TIP]
> Prioritize bypassing obfuscation and instrumenting runtime behavior with precision. Craft targeted Frida hooks to demonstrate maximum impact, including data exfiltration and persistence mechanisms.
