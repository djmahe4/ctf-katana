# CTFd Management Skill

This skill allows the Purple Engine agents to manage the CTFd platform, including challenge creation, flag updates, and user management.

## Guidelines
- Use the provided API client to interact with CTFd.
- Ensure all challenge flags are obfuscated using the standard Purple Engine patterns.
- Always verify the security posture after updating a challenge.
- Support both administrative tasks and participant-side queries.

## Protection-as-Code (PaC)
Integrate with kavach_shield to ensure the platform itself is hardened during management operations.
