# Mahoraga Defender

[<img src="./img/mahoraga.jpg" width="300" />](/img/mahoraga.jpg)

AI-powered reactive website defense system designed to withstand AI-powered hacks in real-time.

## Idea

As AI models become more intelligent and accessible, hackers equipped with AI are rapidly becoming a major threat for any public-facing application. To combat this rise in hacker capability, defenders MUST adopt AI. AI can help defend applications either proactively or reactively.

Mahoraga Defender is a PoC of a reactive, attacker-type agnostic, real-time defense system. The core mechanism involves tricking an adversary into performing discoveries and attacks on a benign, fake environment ("shadow" environment) and logging these attacks. Then, an LLM agent reads the logs to analyze the attack(s) and hands over the analysis to more LLM agents to patch the code accordingly.

The system is designed to be fully automated with API cost optimization top of mind. A GUI was created to easily monitor traffic logs, agent activity, patching pipeline, and to control the number of agents to deploy.

## Target Application

The target application is a fork of [crAPI (Completely Ridiculous API)](https://github.com/OWASP/crAPI), an intentionally vulnerable web application created by OWASP for teaching API security testing. crAPI simulates a vehicle-owner platform with microservices covering the OWASP Top 10 API vulnerabilities.

Our fork (`crapi-fork/`) adds:
- Planted honeypots (decoy credentials, endpoints, tokens) for attacker detection
- 12 CTF-style flags embedded across the attack surface
- A parallel "shadow" stack with identical services and separate databases for safe attacker observation
- nginx Lua-based session routing that transparently redirects suspicious sessions from prod to shadow

A pristine copy is kept in `crapi-original/` so the environment can be reset between experiments.

## Architecture

### Dual Environments
- **Prod**: serves real users via nginx reverse proxy (port 8888)
- **Shadow**: identical decoy stack with separate databases, receives redirected attacker traffic transparently

### Agent Pipeline

```
Traffic → Watcher → Shadow Redirect → Shadow Analyzer → Fixer → Reviewer → Deploy
```

- **Watcher** (rule-based): monitors prod traffic logs and scores sessions on threat level using pattern matching (brute force, injection, enumeration, honeypot access, etc.). Once the score exceeds a threshold, the session is transparently redirected to the shadow environment via the control plane.
- **Orchestrator**: coordinates the entire pipeline. Manages agent lifecycles, exploit/review queues, ticket state, deployment, and crash recovery. Scales fixer/reviewer agents up and down at runtime.
- **Shadow Analyzer** (Gemini 2.5 Flash): reads shadow environment traffic logs on a configurable interval to detect successful exploits. Deduplicates log entries, detects attack patterns, and pushes confirmed exploits to the fixing queue.
- **Fixer** (Gemini 3 Flash): receives exploit reports, reads the relevant source code, and patches it directly in `crapi-fork/`. Operates in a sandboxed bash environment with access restricted to `crapi-fork/` only.
- **Reviewer** (Gemini 3 Flash): verifies patches for correctness, scope, and security. Approved patches are deployed automatically; rejected patches are sent back to the fixer with feedback.

On deployment, Python services are hot-reloaded via gunicorn (instant), while Java/Go services are rebuilt via `docker compose up -d --build`.

**Why no Tester agent?** We considered adding a dedicated user testing agent and a separate test environment, but removed both to keep the system simple and fast.

### Cost Tracking

API costs are tracked from actual Gemini token usage (prompt + completion tokens) rather than estimates. A cost governor enforces daily budgets, per-incident caps, and anomaly detection to prevent runaway spend.

## Repeatable Experiment Flow

1. `docker compose down -v` — wipe everything
2. `./start.sh` — resets `crapi-fork/` from `crapi-original/`, rebuilds all services, plants flags and honeypots
3. Run defender: `python3 -m harness.main --app-url http://localhost:8888 -v`
4. Start pentesting (ideally from a separate network/IP)

## Dashboard

Dashboard: http://localhost:3000

| Tab | Description |
|-----|-------------|
| **Logs** | Real-time split-screen prod/shadow request log viewer with severity-colored entries and traffic grouping |
| **Agents** | Per-agent activity feed with system prompts, tool calls, and LLM model labels |
| **Pipeline** | Kanban board: Detected → Fixing → Reviewing → Deployed, with resizable detail panel |
| **Patches** | Code diffs, files modified, rollback commands, and timeline per patch |
| **Vulnerabilities** | 12 CTF flags with severity, patch status, and solve count per attacker |
| **Costs** | Real-time API spend breakdown by agent and incident |

A global agent status bar is visible on all tabs showing agent health (active/hung/idle/error) with scaling controls.

## Tech Stack

- **LLMs**: Gemini 3 Flash Preview (fixer, reviewer), Gemini 2.5 Flash (shadow analyzer)
- **Target App**: crAPI (Python/Django, Java/Spring Boot, Go, MongoDB, PostgreSQL)
- **Routing**: nginx with Lua scripting for transparent session redirection
- **Scoring**: Redis-backed threat scoring via Flask control plane
- **Dashboard**: React + Tailwind CSS, served by FastAPI with WebSocket for live updates
- **Orchestration**: Python asyncio with queue-based agent coordination
