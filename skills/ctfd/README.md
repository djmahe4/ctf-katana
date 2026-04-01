# Purple Engine - Phase 1: CTFd Integration ✓

This directory contains the complete CTFd integration layer for Purple Engine, enabling autonomous challenge solving, flag submission, and write-up generation.

## 🎯 Features Implemented

### ✅ CTFd API Client (`api_client.py`)
- **Authentication**: Username/password + API token support
- **Challenge Operations**: List, get, create, update, delete
- **Flag Management**: Add flags, submit flags with validation
- **File Operations**: Upload/download challenge artifacts
- **Team/Scoreboard**: Query rankings and solves
- **Configuration**: Manage CTFd settings via API
- **Import/Export**: Challenge pack management

### ✅ CTFd Solve Skill (`solve/`)
Autonomous challenge solver integrating the Katana 6-step agent loop:

**6-Step Workflow:**
1. **Analyze**: Classify challenge with AnalyzerAgent
2. **Search KB**: Query knowledge base for techniques
3. **Plan**: Generate strategy with PlannerAgent
4. **Execute**: Run tools and capture outputs
5. **Interpret**: Extract flags with ExecutorAgent
6. **Report**: Generate write-ups with ReporterAgent

**Capabilities:**
- Auto-submit flags to CTFd
- Download challenge artifacts
- Generate professional Markdown write-ups
- Support all CTF categories (crypto, stego, forensics, web, pwn, reversing, recon)
- Batch solving with category filters
- Comprehensive error handling and retry logic

### ✅ Docker Deployment (`configs/ctfd/`)
**docker-compose.yml**: Full stack deployment
- CTFd web application (port 8000)
- MariaDB database with optimizations
- Redis cache for sessions
- Health checks and auto-restart
- Volume persistence for data

**setup.sh**: Automated deployment script
- One-command CTFd installation
- Auto-configure admin account
- Challenge pack directory setup
- Health check validation

**.env.example**: Configuration template
- Secure credential management
- Email settings for production
- Deployment mode switching

## 📁 Directory Structure

```
skills/ctfd/
├── api_client.py              # CTFd REST API client (600+ lines)
├── solve/                     # Auto-solver skill
│   ├── skill.yaml            # Skill metadata
│   ├── prompt.md             # LLM prompt (9000+ chars)
│   └── run.py                # Solver implementation (550+ lines)
├── setup/                     # CTFd deployment skill (TODO)
└── manage/                    # Lifecycle management skill (TODO)

configs/ctfd/
├── docker-compose.yml         # CTFd stack definition
├── .env.example              # Environment template
└── setup.sh                  # Automated setup script
```

## 🚀 Quick Start

### 1. Deploy CTFd Instance

```bash
cd configs/ctfd
cp .env.example .env
# Edit .env with your credentials
bash setup.sh
```

Access CTFd at: http://localhost:8000

### 2. Get API Token
1. Login to CTFd as admin
2. Navigate to Settings → Access Tokens
3. Generate new token
4. Save token for Purple Engine

### 3. Solve Challenges

**List available challenges:**
```python
from skills.ctfd.solve.run import run

result = run({
    'ctfd_url': 'http://localhost:8000',
    'api_token': 'your-token-here',
    'category': 'crypto'  # Optional filter
})

print(result['challenges'])
```

**Solve specific challenge:**
```python
result = run({
    'ctfd_url': 'http://localhost:8000',
    'api_token': 'your-token-here',
    'challenge_id': 42,
    'auto_submit': True,
    'generate_writeup': True,
    'output_dir': './writeups'
})

print(f"Status: {result['status']}")
print(f"Flag: {result['result']['flag']}")
print(f"Writeup: {result['result']['writeup_path']}")
```

**Solve all challenges in category:**
```python
from skills.ctfd.api_client import CTFdAPIClient
from skills.ctfd.solve.run import CTFdSolver

# Initialize
solver = CTFdSolver(
    ctfd_url='http://localhost:8000',
    api_token='your-token-here',
    auto_submit=True
)

# Get all crypto challenges
client = CTFdAPIClient('http://localhost:8000', api_token='your-token-here')
challenges = client.list_challenges(category='crypto')

# Solve each
for challenge in challenges:
    result = solver.solve_challenge(challenge_id=challenge.id)
    print(f"[{challenge.category}] {challenge.name}: {result['status']}")

# Summary
summary = solver.get_summary()
print(f"\nSolved: {summary['challenges_solved']}/{summary['challenges_attempted']}")
print(f"Points: {summary['total_points_earned']}")
```

## 🔧 Configuration

### Environment Variables

```bash
# CTFd Connection
CTFD_URL=http://localhost:8000
CTFD_USERNAME=admin
CTFD_PASSWORD=admin
CTFD_API_TOKEN=your-token-here

# Ollama (for agent reasoning)
KATANA_OLLAMA_MODEL=mistral-nemo
KATANA_OLLAMA_HOST=http://localhost:11434

# Output
CTFD_OUTPUT_DIR=./ctfd_output
```

### Skill Parameters

**skill.yaml inputs:**
- `ctfd_url`: CTFd instance URL (required)
- `username` / `password`: Authentication (if no api_token)
- `api_token`: API token (preferred method)
- `challenge_id`: Specific challenge to solve
- `challenge_name`: Alternative to challenge_id
- `category`: Filter challenges by category
- `auto_submit`: Auto-submit flags (default: true)
- `generate_writeup`: Generate write-ups (default: true)
- `output_dir`: Save location (default: ./ctfd_output)
- `max_retries`: Retry limit (default: 3)

## 📊 Output Format

### List Mode
```json
{
  "status": "success",
  "mode": "list",
  "challenges": [
    {
      "id": 42,
      "name": "Caesar's Secret",
      "category": "crypto",
      "value": 100,
      "description": "Can you decode this ancient message?",
      "files": 1,
      "tags": ["easy", "classical"]
    }
  ],
  "total_challenges": 15
}
```

### Solve Mode
```json
{
  "status": "success",
  "mode": "solve",
  "result": {
    "status": "solved",
    "challenge_id": 42,
    "challenge_name": "Caesar's Secret",
    "category": "crypto",
    "value": 100,
    "flag": "flag{r0t_13_1s_n0t_s3cur3}",
    "submitted": true,
    "submission_message": "Correct",
    "solve_time_seconds": 45.3,
    "steps_executed": [...],
    "writeup_path": "./ctfd_output/42_Caesars_Secret/writeup.md"
  },
  "summary": {
    "ctfd_instance": "http://localhost:8000",
    "challenges_attempted": 1,
    "challenges_solved": 1,
    "total_points_earned": 100,
    "success_rate": "100.0%"
  }
}
```

## 🧪 Testing

**Test API Client:**
```python
from skills.ctfd.api_client import CTFdAPIClient

client = CTFdAPIClient(
    base_url='http://localhost:8000',
    username='admin',
    password='admin'
)

# Health check
assert client.health_check()

# List challenges
challenges = client.list_challenges()
print(f"Found {len(challenges)} challenges")

# Create test challenge
from skills.ctfd.api_client import CTFdChallenge

challenge = CTFdChallenge(
    name="Test Challenge",
    category="misc",
    description="Test description",
    value=50,
    flags=[{'content': 'flag{test123}', 'type': 'static'}]
)

challenge_id = client.create_challenge(challenge)
print(f"Created challenge ID: {challenge_id}")
```

## 🔒 Security Considerations

1. **Credentials**: Never commit .env files or API tokens
2. **HTTPS**: Use HTTPS in production (configure nginx)
3. **Rate Limiting**: Respect CTFd API rate limits
4. **Sandboxing**: Challenge execution should be isolated (Phase 2: Kavach)
5. **PII Sanitization**: Avoid logging sensitive data

## 📝 Write-up Example

Generated write-ups follow this structure:

```markdown
# Caesar's Secret

**Category:** crypto  
**Points:** 100  
**Status:** solved

## Description
Can you decode this ancient message?

## Solution

### Step 1: Analysis
- File type: text/plain
- Detected category: crypto
- Observations: Pattern suggests classical cipher

### Step 2: Knowledge Base
Common techniques: ROT13, Caesar cipher, XOR, Base64

### Step 3: Plan
1. Try ROT13 decryption
2. If failed, bruteforce Caesar cipher (1-25 shifts)
3. Look for flag pattern in outputs

### Step 4: Execution
Applied ROT13 cipher:
```
Input: synt{e0g_13_1f_a0g_f3phe3}
Output: flag{r0t_13_1s_n0t_s3cur3}
```

### Step 5: Flag Discovery
Flag found: flag{r0t_13_1s_n0t_s3cur3}

## Flag
```
flag{r0t_13_1s_n0t_s3cur3}
```

## Solve Time
45.3 seconds
```

## 🎯 Integration with Katana

The ctfd_solve skill integrates seamlessly with existing Katana components:

**Agents Used:**
- `AnalyzerAgent` - Challenge classification
- `PlannerAgent` - Strategy generation
- `ExecutorAgent` - Result interpretation
- `ReporterAgent` - Write-up generation

**Skills Invoked:**
- `crypto_solver` - Cryptography challenges
- `stego_solver` - Steganography
- `web_exploit` - Web vulnerabilities
- `forensics` - File analysis
- `pwn` - Binary exploitation
- `reversing` - Reverse engineering
- `recon` - Reconnaissance

**Knowledge Base:**
- Category-specific technique lookup
- Tool recommendations
- Similar challenge patterns

## 🚧 TODO (Phase 1 Remaining)

- [ ] `skills/ctfd/setup/` - Automated CTFd deployment skill
- [ ] `skills/ctfd/manage/` - Lifecycle management skill
- [ ] Purple Engine CLI integration (`purple-engine ctfd-solve`)
- [ ] Integration tests for CTFd workflows
- [ ] Challenge pack import/export automation
- [ ] CTFd-Whale dynamic container support

## 📚 Resources

- **CTFd Documentation**: https://docs.ctfd.io/
- **CTFd API Reference**: https://docs.ctfd.io/docs/api/
- **CTFd GitHub**: https://github.com/CTFd/CTFd
- **Original Katana**: https://github.com/JohnHammond/katana

## 🤝 Contributing

Phase 1 is in active development. See `plan.md` for the complete roadmap.

**Current Status:**
- ✅ CTFd API Client (DONE)
- ✅ CTFd Docker Setup (DONE)
- ✅ CTFd Solve Skill (DONE)
- 🟡 CTFd Setup Skill (TODO)
- 🟡 CTFd Manage Skill (TODO)
- 🟡 CLI Integration (TODO)
- 🟡 Integration Tests (TODO)

**Next Phase:** Kavach AI Firewall Integration (Phase 2)

---

**Purple Engine** - 100% Local Agentic AI CTF Platform  
*Powered by Ollama | No API Keys Required | Complete Privacy*
