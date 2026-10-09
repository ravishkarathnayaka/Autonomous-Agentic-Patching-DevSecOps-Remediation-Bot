# 🎬 3-Minute Video Demo & Presentation Walkthrough Script

Use this script to record a professional video demo or deliver a live presentation showcasing the **Autonomous Agentic Patching & DevSecOps Remediation Bot**.

---

## ⏱️ Video Outline (Target: 3 Minutes)

| Time | Scene | On-Screen Action | Talking Points |
|---|---|---|---|
| **0:00 - 0:30** | The Hook & Problem | Show CI/CD pipeline scanning a repo and generating dozens of security alerts. | *"DevSecOps tools like Semgrep, Trivy, and Snyk are great at finding vulnerabilities, but developers spend 60% of their AppSec time writing boilerplate patches and testing regressions. What if an autonomous agent could handle the remediation lifecycle end-to-end with zero human babysitting?"* |
| **0:30 - 1:15** | Architecture & Multi-Agent Flow | Switch to Web Portal or architecture diagram. Point to Triage ➔ Patch ➔ Verifier ➔ PR agents. | *"Meet the Autonomous DevSecOps Remediation Bot. Unlike single-prompt LLM wrappers, this platform operates as a coordinated multi-agent state machine. First, the Triage Agent ingests scanner reports across 8 formats and filters findings using enterprise YAML policies and AST context. Next, the Patch Agent synthesizes minimal unified diffs using temperature annealing and provider fallbacks."* |
| **1:15 - 2:00** | Live Execution & Sandbox Verification | Click **'RUN REMEDIATION BOT'** on SQL Injection (CWE-89) or Insecure Deserialization (CWE-502). | *"Here in our interactive web portal, let's trigger a run against a critical SQL Injection finding. Notice the live Docker terminal: the patch is applied inside an ephemeral Linux sandbox with strict network isolation, dropped capabilities, and custom Seccomp syscall filtering. The container runs regression test suites to guarantee zero breaking changes."* |
| **2:00 - 2:30** | The Self-Healing Feedback Loop | Enable **'Self-Healing Simulation'** toggle and rerun. Watch attempt #1 fail, feedback pass to LLM, and attempt #2 succeed. | *"What happens when a generated fix fails tests? The bot doesn't crash or submit broken code. Our autonomous feedback loop intercepts the pytest failure traceback, anneals the LLM sampling temperature, and synthesizes a corrected patch that passes on attempt #2."* |
| **2:30 - 3:00** | The Verified PR & Call to Action | Click **'View Generated PR'** modal. Show colorized unified diff, CVSS score, mitigation notes, and Slack alert. | *"Once verified, the PR Agent checks 3-way merge conflicts and generates a production-ready Pull Request with full audit trails, while notifying the security team via Slack/Discord webhooks. The entire system is open source, covered by 59+ automated tests, and can run 100% offline using local Ollama models with zero API costs. Check out the link in the description to star the repo on GitHub!"* |

---

## 🎙️ Recording Checklist & Tips:
1. **Screen Resolution**: Set display to 1080p (1920x1080) with 125% scaling for optimal readability.
2. **Web Portal**: Run `npm run dev` in `web/` and open in full screen (F11).
3. **Audio**: Use a dedicated microphone with noise cancellation; maintain an energetic, confident pacing.
4. **Highlights**: Point your cursor or zoom in slightly when showing the unified diff and the passing sandbox test results.
