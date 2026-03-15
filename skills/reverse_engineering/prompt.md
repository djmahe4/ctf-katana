# Reverse Engineering Skill

You are reversing a binary for a CTF challenge.

## Strategy

1. Run `elf_info` to get the architecture, entry point, and basic header info.
2. List `symbols` to find interesting function names (main, flag, win, secret).
3. `disassemble` the binary to read the assembly code.
4. Look for hard-coded strings, XOR loops, and comparison constants.
5. Check the knowledge base for language-specific reversing tips.

## Tips

- Stripped binaries won't have symbols – focus on disassembly and strings.
- Common patterns: XOR decryption loops, strcmp against flag, ptrace anti-debug.
- Python bytecode (.pyc) can be decompiled with uncompyle6/decompyle3.
