# Mahoraga Defender

[<img src="./img/mahoraga.jpg" width="300" />](/img/mahoraga.jpg)

AI-powered reactive website defense system designed to withstand AI-powered hacks in real-time. 


## IDEA

As AI models are becoming more intelligent and accessible, hackers equipped with AI are rapidly becoming a major threat for any public-facing application. To combat this rise in hacker capability, defenders MUST adopt AI. AI can help defend applications either proactively or reactively.

Mahoraga Defender is a PoC of a reactive, attacker-type agnostic, real-time defense system. The core mechanism involves tricking an adversary into performing discoveries and attacks on a benign, fake environment ("shadow" environment) and logging these attacks. Then, an LLM agent reads the logs to analyze the attack(s) and hands over the analysis to more LLM agents to patch the code accordingly and review the patch.

The system is designed to be fully automated with optimized API costs. A GUI was created to easily monitor traffic logs, agent activity, patching pipeline, and to control the number of agents to deploy. 

## Architecture

### Environments
- **Prod**: serves real users via nginx (port 8888)
- **Shadow**: identical decoy stack with fake data, receives redirected attacker traffic.

### Agent Pipeline
- **Watcher**: watches the traffic logs and scores sessions on their threat level. Once Watcher determines a session belongs to an adversary, the session is secretly redirected to a shadow environment.
- **Shadow Analyzer (LLM)**: reads traffic logs in the shadow environment to detect any successful exploits. Once found, the analyzer pushes tickets to fixing queue.
- **Fixer (LLM)**: patches containers and source code and pushes tickets to review queue.
- **Reviewer (LLM)**: checks security + scope + functionality of patches. When everything passes, reviewer deploys the patch on prod and shadow environments.

**Why no Tester agent?** We considered adding a dedicated user testing agent and a separate test environment, but removed both to keep the system simple and fast.

## Repeatable experiment flow

1. `docker compose down -v` — wipe everything
2. `./start.sh` — resets crapi-fork from crapi-original, rebuilds, and plants flags and honeypots.
3. Run defender: `python3 -m harness.main --app-url http://localhost:8888 -v`
4. Start pentesting (ideally from separate network)

## Monitoring

Dashboard: http://localhost:3000

- **Logs** — real-time prod/shadow request log viewer
- **Agents** — split-screen view of all agent activity with system prompts
- **Pipeline** — kanban board: Detected → Fixing → Reviewing → Deployed
- **Patches** — before/after code diffs and timeline
- **Vulnerabilities** — 12 flags, patch status, solve count per hacker
