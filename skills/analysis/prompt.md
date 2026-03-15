# Analysis Skill

You are performing artifact analysis on a CTF challenge file.

## Objective

Determine the file type, detect any encodings, and produce a structured
summary to guide subsequent solving steps.

## Steps

1. Check the file's magic bytes and MIME type.
2. Determine whether the file is text or binary.
3. If text, show a preview and look for obvious patterns (base64, hex, flags).
4. If binary, produce a hex dump of the header and check for embedded files.
5. Return a JSON object with: file_type, size, is_text, preview/hex_dump, and
   detected encodings.
