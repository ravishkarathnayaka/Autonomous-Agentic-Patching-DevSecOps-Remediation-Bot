import { AgentLog, Finding, RemediationResult } from '../types';
import { PresetScenario } from '../data/scenarios';

type UpdateCallback = (state: RemediationResult) => void;

const delay = (ms: number) => new Promise((res) => setTimeout(res, ms));

export async function runRemediationPipeline(
  scenario: PresetScenario,
  simulateRetry: boolean,
  onUpdate: UpdateCallback
): Promise<RemediationResult> {
  const logs: AgentLog[] = [];
  const finding: Finding = scenario.finding;

  const pushLog = (agent: any, message: string, type: 'info' | 'success' | 'warning' | 'error' = 'info', details?: string) => {
    const log: AgentLog = {
      id: Math.random().toString(36).substring(7),
      timestamp: new Date().toLocaleTimeString(),
      agent,
      message,
      type,
      details
    };
    logs.push(log);
  };

  let currentState: RemediationResult = {
    finding,
    status: 'TRIAGING',
    retryCount: 0,
    maxRetries: 3,
    logs
  };

  // ==========================================
  // 1. TRIAGE AGENT
  // ==========================================
  pushLog('TriageAgent', `Ingesting ${finding.scanner.toUpperCase()} finding: ${finding.ruleId}`, 'info');
  onUpdate({ ...currentState, status: 'TRIAGING' });
  await delay(700);

  pushLog('TriageAgent', `Resolved source path: ${finding.filePath} (lines ${finding.startLine}-${finding.endLine})`, 'info');
  await delay(600);

  pushLog('TriageAgent', `Extracted AST context: ${finding.astContext || 'Local module scope'}`, 'success');
  currentState = { ...currentState, status: 'PATCHING' };
  onUpdate(currentState);
  await delay(600);

  // ==========================================
  // 2. PATCH & VERIFY (WITH SELF-HEALING LOOP)
  // ==========================================
  let isVerified = false;
  let attempts = 0;

  while (!isVerified && attempts < currentState.maxRetries) {
    attempts++;
    currentState.retryCount = attempts - 1;

    // PATCH AGENT
    const isFailedAttempt = simulateRetry && attempts === 1;
    pushLog(
      'PatchAgent',
      attempts > 1 
        ? `Self-Healing Retry (${attempts}/3): Ingesting verifier diagnostics into LLM prompt...` 
        : `Orchestrating prompt for ${finding.cwe.join(', ') || finding.ruleId}...`,
      attempts > 1 ? 'warning' : 'info'
    );
    currentState = { ...currentState, status: 'PATCHING' };
    onUpdate(currentState);
    await delay(1000);

    const generatedDiff = isFailedAttempt ? scenario.failingPatchDiff : scenario.passingPatchDiff;
    currentState.patchDiff = generatedDiff;
    currentState.patchExplanation = scenario.remediationExplanation;

    pushLog('PatchAgent', `Generated surgical unified diff (${generatedDiff.split('\n').length} lines)`, 'success');
    currentState = { ...currentState, status: 'VERIFYING' };
    onUpdate(currentState);
    await delay(800);

    // VERIFIER AGENT
    pushLog('VerifierAgent', `Spawning ephemeral Docker sandbox (network_disabled=True, cap_drop=[ALL])...`, 'info');
    onUpdate(currentState);
    await delay(900);

    if (isFailedAttempt) {
      pushLog('VerifierAgent', `Pre-flight syntax check FAILED: SyntaxError: unexpected EOF while parsing`, 'error');
      pushLog('VerifierAgent', `Pytest functional suite exited with code 2. Triggering self-healing feedback loop.`, 'warning');

      currentState.verification = {
        passed: false,
        functionalTestsPassed: false,
        securityTestsPassed: false,
        syntaxValid: false,
        testOutput: `============================= test session starts =============================\nERROR collecting target_repo/app.py\nSyntaxError: unexpected EOF while parsing (line 29)\n============================== 1 error in 0.32s ===============================`,
        securityOutput: `Security scan aborted due to syntax errors.`,
        durationSeconds: 0.32
      };

      currentState.status = 'RETRY_NEEDED';
      onUpdate(currentState);
      await delay(1200);
      continue;
    } else {
      pushLog('VerifierAgent', `Pre-flight AST syntax check PASSED (clean ast.parse)`, 'success');
      await delay(600);

      pushLog('VerifierAgent', `Running functional regression suite: pytest test_app.py -v`, 'info');
      await delay(1000);

      currentState.verification = {
        passed: true,
        functionalTestsPassed: true,
        securityTestsPassed: true,
        syntaxValid: true,
        testOutput: `============================= test session starts =============================\nplatform linux -- Python 3.11.8, pytest-8.1.1\n\ntest_app.py::test_search_valid PASSED                                    [ 33%]\ntest_app.py::test_file_view_valid PASSED                                 [ 66%]\ntest_app.py::test_ping_valid PASSED                                      [100%]\n\n============================== 3 passed in 0.84s ==============================`,
        securityOutput: `Semgrep re-scan passed: 0 security findings flagged.`,
        durationSeconds: 0.84
      };

      pushLog('VerifierAgent', `Verification PASSED: Zero regressions, vulnerability eliminated in sandbox!`, 'success');
      isVerified = true;
      currentState.status = 'VERIFIED';
      onUpdate(currentState);
      await delay(800);
    }
  }

  // ==========================================
  // 3. PR AGENT
  // ==========================================
  if (isVerified) {
    const timestamp = new Date().toISOString().replace(/[-:T.]/g, '').slice(0, 14);
    const cweSlug = (finding.cwe[0] || 'remediation').toLowerCase().replace(/[^a-z0-9]/g, '-');
    const branchName = `security/fix-${cweSlug}-${timestamp}`;
    const commitSha = Math.random().toString(16).substring(2, 10);
    const title = `fix(security): remediate ${finding.title} (${(finding.cwe[0] || '').toUpperCase()})`;

    pushLog('PRAgent', `Establishing dedicated security branch: ${branchName}`, 'info');
    await delay(600);

    pushLog('PRAgent', `Created atomic git commit: ${commitSha}`, 'info');
    await delay(500);

    const prMarkdown = `## 🛡️ Autonomous Security Remediation Pull Request

### 1. Executive Summary
- **Vulnerability Title**: ${finding.title}
- **Scanner**: \`${finding.scanner.toUpperCase()}\` (${finding.type})
- **Rule / Advisory ID**: \`${finding.ruleId}\`
- **Severity**: **\`${finding.severity}\`**
- **CWE Identifier(s)**: \`${finding.cwe.join(', ')}\`
- **CVSS Score**: \`${finding.cvss}\`
- **Target File**: \`${finding.filePath}\` (Lines ${finding.startLine} - ${finding.endLine})

---

### 2. Threat Analysis & Remediation Rationale
${scenario.remediationExplanation}

#### Security Controls Applied:
- Surgical code modification targeting only the vulnerable execution flow.
- Enforced defense-in-depth principles (parameterized queries & boundary checks).
- Preserved existing application semantics and interface contracts.

---

### 3. Surgical Patch Diff
\`\`\`diff
${scenario.passingPatchDiff}
\`\`\`

---

### 4. Sandbox Verification Evidence
> **Verification Status**: ✅ **PASSED** (Executed inside Ephemeral Container Sandbox)  
> **Total Attempts / Retries**: \`${attempts}\` / \`3\`  
> **Execution Duration**: \`0.84s\`

\`\`\`text
${currentState.verification?.testOutput}
\`\`\`

---

### 5. DevSecOps Sign-off & Verification Checklist
- [x] Ephemeral sandbox execution verified without host compromise.
- [x] Zero regression in existing unit test suites (\`pytest\`).
- [x] Clean syntax and AST structure verified.
- [ ] Peer code review and security sign-off before merge.

---
*Generated autonomously by [Autonomous Agentic Patching & DevSecOps Remediation Bot](https://github.com/ravishkarathnayaka/Autonomous-Agentic-Patching-DevSecOps-Remediation-Bot).*`;

    currentState = {
      ...currentState,
      status: 'PR_READY',
      prBranch: branchName,
      prTitle: title,
      commitSha: commitSha,
      prBody: prMarkdown
    };

    pushLog('PRAgent', `Pull Request synthesized with threat analysis & DevSecOps checklist!`, 'success');
    onUpdate(currentState);
  }

  return currentState;
}
