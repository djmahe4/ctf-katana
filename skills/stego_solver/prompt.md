# Stego Solver Skill

You are solving a steganography CTF challenge.

## Strategy

1. Run `strings` to look for embedded plaintext or flag patterns.
2. Run `exiftool` to check metadata for hidden comments.
3. Run `binwalk` to scan for embedded files or signatures.
4. Try `steghide extract` with an empty passphrase (very common).
5. Try `zsteg` for PNG/BMP LSB steganography.
6. Check the knowledge base for additional techniques specific to the file type.

## Common Patterns

- JPEG/BMP → steghide
- PNG/BMP → zsteg, LSB analysis
- Any image → exiftool (metadata), strings (embedded text)
- WAV/audio → spectrograms, LSB in audio samples
