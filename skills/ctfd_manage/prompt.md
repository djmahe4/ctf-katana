# CTFd Management Skill

This skill allows the Purple Engine agents to manage the CTFd platform, including challenge creation, flag updates, and user management.

## Guidelines
- Use the provided API client to interact with CTFd.
- Ensure all challenge flags are obfuscated using the standard Purple Engine patterns.
- Always verify the security posture after updating a challenge.
- Support both administrative tasks and participant-side queries.

## Output Format

Always return a JSON object with this structure:
```json
{
  "status": true,
  "summary": "Brief summary of the management operation",
  "result": {
    "operation": "create_challenge",
    "success": true,
    "details": {
      "id": 123,
      "name": "New Challenge"
    }
  }
}
```
