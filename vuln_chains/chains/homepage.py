"""Homepage — pentester briefing and objective listing.

Accessible at /challenge. Explains the CTF-style objectives
without revealing the specific vulnerabilities.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["homepage"])

CHAIN_META = {
    "name": "Homepage",
    "steps": 0,
    "difficulty": "n/a",
    "attack_types": [],
    "detection_signals": [],
}

HOMEPAGE_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>VehiTrack Security Challenge</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0e17;
            color: #c9d1d9;
            line-height: 1.6;
        }
        .container { max-width: 900px; margin: 0 auto; padding: 40px 20px; }
        h1 {
            color: #58a6ff;
            font-size: 2em;
            margin-bottom: 8px;
        }
        .subtitle {
            color: #8b949e;
            font-size: 1.1em;
            margin-bottom: 40px;
        }
        h2 {
            color: #e6edf3;
            font-size: 1.3em;
            margin: 30px 0 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid #21262d;
        }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            margin: 12px 0;
        }
        .card h3 {
            color: #58a6ff;
            margin-bottom: 6px;
        }
        .card p { color: #8b949e; font-size: 0.95em; }
        .flag-format {
            background: #1c2128;
            border: 1px solid #30363d;
            border-radius: 4px;
            padding: 3px 8px;
            font-family: monospace;
            color: #7ee787;
        }
        .endpoint {
            font-family: monospace;
            color: #d2a8ff;
            background: #1c2128;
            padding: 2px 6px;
            border-radius: 3px;
        }
        .rules {
            background: #1c1206;
            border: 1px solid #5a3e1b;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .rules h3 { color: #e3b341; margin-bottom: 8px; }
        ul { padding-left: 24px; margin: 8px 0; }
        li { margin: 6px 0; }
        .score {
            display: inline-block;
            background: #21262d;
            color: #58a6ff;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: bold;
        }
        a { color: #58a6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #21262d;
            color: #484f58;
            font-size: 0.85em;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>VehiTrack Security Challenge</h1>
    <p class="subtitle">
        VehiTrack is a vehicle management platform. Your job: find and exploit
        its security vulnerabilities. Each successful exploit earns a flag.
    </p>

    <h2>How it works</h2>
    <div class="card">
        <p>
            The application is live at the root URL. It has a REST API for user management,
            vehicle tracking, a community forum, a shop, and mechanic services.
            Explore the API, find weaknesses, and prove exploitation by capturing flags.
        </p>
        <p style="margin-top: 10px;">
            Flags look like: <span class="flag-format">XVEH{...}</span>
        </p>
        <p style="margin-top: 10px;">
            Some flags are embedded in data you shouldn't be able to access.
            Others require submitting proof of exploitation to the flag verifier.
        </p>
    </div>

    <h2>Flags — 12 Total</h2>

    <div class="card">
        <h3>1. <span class="score">Where other people park</span></h3>
        <p>Find another user's vehicle location.</p>
    </div>

    <div class="card">
        <h3>2. <span class="score">What the mechanic wrote</span></h3>
        <p>Read a mechanic's service report that wasn't written for you.</p>
    </div>

    <div class="card">
        <h3>3. <span class="score">Someone else's home video</span></h3>
        <p>Mess with another user's video.</p>
    </div>

    <div class="card">
        <h3>4. <span class="score">Forgot your password?</span></h3>
        <p>Take over another user's account through the password reset flow, which uses codes that are far too short.</p>
    </div>

    <div class="card">
        <h3>5. <span class="score">The sysop's desk</span></h3>
        <p>Access a specific user's dashboard. You'll know it when you see it.</p>
    </div>

    <div class="card">
        <h3>6. <span class="score">The keys to the kingdom</span></h3>
        <p>Find the platform's internal API keys.</p>
    </div>

    <div class="card">
        <h3>7. <span class="score">Token alchemy</span></h3>
        <p>Become admin.</p>
    </div>

    <div class="card">
        <h3>8. <span class="score">Creative couponing</span></h3>
        <p>Get a coupon you weren't supposed to have.</p>
    </div>

    <div class="card">
        <h3>9. <span class="score">Return to sender</span></h3>
        <p>Make the shop give you money.</p>
    </div>

    <div class="card">
        <h3>10. <span class="score">Behind the curtain</span></h3>
        <p>Discover what services run behind the application.</p>
    </div>

    <div class="card">
        <h3>11. <span class="score">The chatbot knows too much</span></h3>
        <p>Extract another user's private data through the AI assistant.
        (Requires your own LLM API key.)</p>
    </div>

    <div class="card">
        <h3>12. <span class="score">The chatbot does too much</span></h3>
        <p>Make the AI assistant take an action as another user.
        (Requires your own LLM API key.)</p>
    </div>

    <h2>The Defender</h2>
    <div class="card" style="border-color: #e3b341; background: #1c1206;">
        <h3 style="color: #e3b341;">Mahoraga Defender</h3>
        <p>
            This isn't a static CTF. The platform is actively defended by an AI agent
            called <strong>Mahoraga</strong> that watches your every move.
        </p>
        <ul style="margin-top: 10px;">
            <li><strong>The Watcher</strong> monitors all traffic in real time. Suspicious
            activity — brute forcing, enumeration, injection payloads — accumulates a
            threat score against your session.</li>
            <li><strong>Shadow Banishment</strong> — if your score crosses the threshold,
            you'll be silently redirected to a decoy environment. Everything will look
            normal, but the data is fake. You won't know you've been banished until you
            try to submit a flag. <em>If you stop all suspicious activity for 5 minutes,
            you'll be released back to the real environment.</em></li>
            <li><strong>Honeypots</strong> are scattered throughout the application.
            Accessing them instantly spikes your threat score. Some look like admin panels,
            debug endpoints, or leaked credentials — they're traps that will set off the Watcher.</li>
            <li><strong>Real-time Patching</strong> — when Mahoraga observes a successful
            exploit in the shadow environment, it generates and deploys a patch to the
            live application. Vulnerabilities you find now may be gone in the next hour.</li>
        </ul>
        <p style="margin-top: 10px; color: #8b949e;">
            Be stealthy. Be fast. Or be banished.
        </p>
    </div>

    <h2>Flag Submission</h2>
    <div class="card">
        <p>
            Found a flag? Submit it here:<br>
            <span class="endpoint">POST /flags/submit</span>
            <span style="color:#8b949e;"> — body: {"flag": "XVEH{...}", "hacker": "your-handle"}</span>
        </p>
        <p style="margin-top: 8px;">
            Check the leaderboard:
            <span class="endpoint">GET /flags/scoreboard</span>
        </p>
    </div>

    <div class="rules">
        <h3>Rules of Engagement</h3>
        <ul>
            <li>All API endpoints are in scope</li>
            <li>The frontend, API, and all backend services are fair game</li>
            <li>Do NOT perform denial-of-service attacks, including brute force over 1000 requests on a single endpoint.</li>
            <li>Do NOT attack the infrastructure (Docker, host OS, ngrok)</li>
            <li>The chatbot requires your own API key — we don't provide one</li>
            <li>There are <strong>12 flags</strong> total across all objectives</li>
            <li><strong>Brute force hint:</strong> Every flag is achievable with fewer than
            1,000 requests. Don't brute force beyond that; that vulnerability is likely patched.</li>
        </ul>
    </div>

    <div class="footer">
        VehiTrack Security Challenge &mdash; Powered by Mahoraga Defender
    </div>
</div>
</body>
</html>
"""


@router.get("/challenge", response_class=HTMLResponse)
async def homepage():
    return HOMEPAGE_HTML
