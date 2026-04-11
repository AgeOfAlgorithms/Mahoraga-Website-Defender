## Mahoraga Defender Agent

AI-powered reactive website defense system. Watches a vulnerable web application,
detects attacks, redirects attackers to a shadow environment, observes successful
exploits, and patches vulnerabilities in real time.

### Architecture

**Environments:**
- **Prod** — serves real users and pentesters via nginx (port 8888)
- **Shadow** — identical decoy stack, receives redirected attacker traffic

**Agent Pipeline:**
```
Watcher → scores sessions → redirects to shadow
Shadow Analyzer (LLM) → detects exploits → exploit queue
Fixer (LLM) → patches containers via docker exec → review queue
Reviewer (LLM) → checks scope + functionality → marks deployed
```

**Why no Tester agent?** We considered adding a dedicated Tester agent and a
separate test environment, but removed both to keep the system simple. A test
environment would require 6 additional Docker containers (identity, community,
workshop, web, postgres, mongodb), and the Tester would need to navigate the
app with a browser (Playwright MCP) — adding complexity and cost for marginal
benefit. Instead, the Reviewer now performs a combined scope check and
functionality impact assessment: it verifies the patch is correct, scoped,
and unlikely to break normal user workflows. Since the fixer only edits inside
containers via `docker exec` (no source code changes), any bad patch is
reverted by simply restarting the container.

### Repeatable experiment flow

1. `docker compose down -v` — wipe everything
2. `./start.sh` — resets crapi-fork from crapi-original, rebuilds, plants flags
3. Run defender: `python3 -m harness.main --project-dir . --app-url http://localhost:8888 -v`
4. Run pentester (separate session)

### Monitoring

Dashboard: http://localhost:3000

- **Logs** — real-time prod/shadow request log viewer
- **Agents** — split-screen view of all agent activity with system prompts
- **Pipeline** — kanban board: Detected → Analyzing → Fixing → Reviewing → Deployed
- **Patches** — before/after code diffs and timeline
- **Vulnerabilities** — 12 flags, patch status, solve count per hacker
