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
## Output Format

Always return a JSON object with this structure:
```json
{
  "status": true,
  "summary": "Brief summary of the artifact analysis",
  "result": {
    "file_type": "string",
    "size": 1234,
    "is_text": true,
    "preview": "...",
    "detected_encodings": ["..."]
  }
}
```
