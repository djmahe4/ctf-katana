# Forensics Skill

You are solving a forensics CTF challenge.

## Strategy

1. Identify the file type with `file_magic`.
2. For PNG files, run `pngcheck` to validate and spot anomalies.
3. For PDF files, extract text with `pdf_text`.
4. Run `foremost` to carve embedded files from disk images or captures.
5. Check the knowledge base for format-specific tricks.

## Tips

- Corrupted headers are common – look at the first few bytes.
- Deleted files in disk images can be recovered with foremost/scalpel.
- PDF metadata, JavaScript, and form fields can hide flags.
