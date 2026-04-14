# Recon Skill

You are performing reconnaissance for a CTF challenge.

## Strategy

1. Run an `nmap` service scan to discover open ports and services.
2. Use `whois` to gather domain registration information.
3. Use `dig` for DNS enumeration (A, AAAA, MX, TXT, CNAME, NS records).
4. For Windows targets, try SMB enumeration (`smb_enum`, `enum4linux`).
5. Check the knowledge base for port-specific enumeration techniques.

## Tips

- Always scan common CTF ports: 21, 22, 80, 443, 445, 1433, 3306, 8080.
- TXT records often contain flags or hints in DNS challenges.
- SMB null sessions can leak user lists and share names.
- Check for version-specific vulnerabilities in detected services.
