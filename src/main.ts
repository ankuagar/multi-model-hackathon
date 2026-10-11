import "./style.css";
import {
  RemediationOrchestrator,
  type AdversarialReviewer,
  type CheckResult,
  type Patch,
  type RemediationRun,
  type RepairAgent,
  type SecurityAlert,
  type TriageAgent,
  type Validator,
} from "./workflow";

const alert: SecurityAlert = {
  id: "DEMO-SQLI-001",
  ruleId: "PATCHFORGE-SQLI-001",
  title: "SQL injection in user lookup",
  severity: "high",
  repository: "demo/unsafe-users-api",
  commit: "fixture-a84d12c",
  filePath: "src/users.ts",
  line: 42,
  description: "User supplied email is concatenated into a SQL query.",
};

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
type DemoScenario = "standard" | "recoverable" | "persistent";
let demoScenario: DemoScenario = "standard";

const triageAgent: TriageAgent = {
  async triage() {
    await sleep(260);
    return {
      vulnerabilityClass: "SQL injection",
      summary: "The user lookup builds a SQL statement with interpolated input. A parameterized query is the narrowest fix.",
      affectedFiles: [alert.filePath],
      complexity: "low",
      confidence: 0.96,
    };
  },
};

const repairAgent: RepairAgent = {
  async propose(_alert, _triage, feedback): Promise<Patch> {
    await sleep(320);
    const safePatch = demoScenario === "standard" || (demoScenario === "recoverable" && feedback.length > 0);
    return {
      changedFiles: [alert.filePath],
      rationale: safePatch
        ? "Bind the email value as a query parameter so it is treated as data."
        : "Simulated flawed attempt: the user value is still interpolated into SQL.",
      diff: [
        "diff --git a/src/users.ts b/src/users.ts",
        "--- a/src/users.ts",
        "+++ b/src/users.ts",
        "@@ -40,2 +40,2 @@ export async function findUser(email: string) {",
        safePatch
          ? "-  const query = `SELECT * FROM users WHERE email = '${email}'`;"
          : "+  const query = `SELECT * FROM users WHERE email = '${email}'`;",
        safePatch ? "-  return db.query(query);" : "+  return db.query(query);",
        ...(safePatch ? [
          "+  const query = \"SELECT * FROM users WHERE email = ?\";",
          "+  return db.query(query, [email]);",
        ] : []),
      ].join("\n"),
    };
  },
};

const adversarialReviewer: AdversarialReviewer = {
  async review(_alert, patch) {
    await sleep(260);
    const usesParameter = patch.diff.includes("WHERE email = ?") && patch.diff.includes("db.query(query, [email])");
    return usesParameter ? [] : [{
      severity: "high",
      title: "User input may still be interpolated",
      detail: "The proposed diff does not show both a placeholder and a bound value.",
      filePath: alert.filePath,
    }];
  },
};

function toyUnsafeLookup(email: string, rows: Array<{ email: string }>) {
  return email === "' OR '1'='1" ? rows : rows.filter((row) => row.email === email);
}

function toyParameterizedLookup(email: string, rows: Array<{ email: string }>) {
  return rows.filter((row) => row.email === email);
}

const validator: Validator = {
  async validate(_alert, patch): Promise<CheckResult[]> {
    await sleep(320);
    const bindsValue = patch.diff.includes("WHERE email = ?") && patch.diff.includes("db.query(query, [email])");
    const rows = [{ email: "alice@example.test" }, { email: "bob@example.test" }];
    const payload = "' OR '1'='1";
    const vulnerableFixtureExposed = toyUnsafeLookup(payload, rows).length > 0;
    const patchedFixtureBlocked = toyParameterizedLookup(payload, rows).length === 0;
    return [
      {
        name: "Parameterized query review",
        passed: bindsValue,
        summary: bindsValue ? "Placeholder and bound value are present in the proposed diff." : "The expected parameter binding was not found.",
      },
      {
        name: "SQLi regression fixture",
        passed: vulnerableFixtureExposed && patchedFixtureBlocked,
        summary: vulnerableFixtureExposed && patchedFixtureBlocked
          ? "The toy fixture reproduces the unsafe case and blocks the payload with the patched lookup."
          : "The toy regression case did not behave as expected.",
        details: "In-memory behavior simulation only; this does not execute SQL or test a real database.",
      },
      {
        name: "Demo workflow assertions",
        passed: bindsValue && patchedFixtureBlocked,
        summary: bindsValue && patchedFixtureBlocked ? "All seeded demo assertions passed." : "One or more seeded demo assertions failed.",
        details: "These are deterministic fixture checks, not repository tests or a security scan.",
      },
    ];
  },
};

const orchestrator = new RemediationOrchestrator({
  triageAgent,
  repairAgent,
  reviewer: adversarialReviewer,
  validator,
  maxRepairAttempts: 3,
});

const htmlEscapes: Record<string, string> = {
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;",
};
const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (char) => htmlEscapes[char]);

const app = document.querySelector<HTMLDivElement>("#app");
if (!app) throw new Error("Missing #app root");

app.innerHTML = `
  <div class="shell">
    <header class="topbar">
      <a class="brand" href="#" aria-label="PatchForge home"><span class="mark">P</span><span>PatchForge</span></a>
      <span class="tag">Interactive fixture · no live integrations</span>
    </header>
    <main>
      <section class="hero">
        <div class="eyebrow">Security remediation, with evidence</div>
        <h1>Fix the alert.<br />Show the proof.</h1>
        <p class="intro">Run a seeded SQL injection issue through triage, repair, independent review, and deterministic fixture checks. Inspect the evidence, then record a human approval.</p>
      </section>
      <section class="workspace">
        <aside class="column">
          <article class="panel alert-panel">
            <div class="section-head"><span class="overline">Seeded alert</span><span class="severity">HIGH</span></div>
            <h2>${escapeHtml(alert.title)}</h2>
            <p class="muted">${escapeHtml(alert.description)}</p>
            <dl class="facts">
              <div><dt>Repository</dt><dd>${escapeHtml(alert.repository)}</dd></div>
              <div><dt>Location</dt><dd>${escapeHtml(alert.filePath)}:${alert.line}</dd></div>
              <div><dt>Rule</dt><dd>${escapeHtml(alert.ruleId)}</dd></div>
            </dl>
          </article>
          <article class="panel safety-note">
            <span class="overline">Demo boundaries</span>
            <p>This run uses fixture agents and an in-memory behavior simulation. It does not connect to a repository, execute SQL, run a real exploit, or perform a security scan.</p>
          </article>
        </aside>
        <section class="column main-column">
          <article class="panel run-panel">
            <div class="run-heading">
              <div><span class="overline">Remediation run</span><h2 id="run-title">Ready to start</h2></div>
              <span id="run-state" class="state-badge">Not started</span>
            </div>
            <label class="scenario-control" for="scenario-select">Demo scenario
              <select id="scenario-select">
                <option value="standard">Standard pass</option>
                <option value="recoverable">One failed attempt, then repair</option>
                <option value="persistent">Repeated failure, escalate to human</option>
              </select>
              <small id="scenario-help">Fixture agents produce a safe patch and pass the checks.</small>
            </label>
            <div id="pipeline" class="pipeline" aria-live="polite"></div>
            <div class="actions">
              <button id="start-run" class="button primary" type="button">Start demo run</button>
              <button id="approve-run" class="button secondary" type="button" disabled>Approve demo patch</button>
            </div>
            <p id="action-note" class="action-note">Approval records a decision in this page only. It does not merge or deploy code.</p>
            <div id="exception-box" class="exception-box" hidden>
              <label for="exception-reason">Human review reason</label>
              <textarea id="exception-reason" rows="3" placeholder="Explain why you are approving despite failed evidence"></textarea>
              <small>This records an explicit exception in the evidence trail. It does not merge or deploy code.</small>
            </div>
          </article>
          <article class="panel evidence-panel">
            <div class="section-head"><span class="overline">Evidence trail</span><span id="attempts" class="muted small"></span></div>
            <div id="evidence" class="empty-state">Start the demo to see triage notes, review results, checks, and the proposed diff.</div>
          </article>
        </section>
      </section>
      <footer>PatchForge prototype · run state is held in this browser tab and resets on reload</footer>
    </main>
  </div>
`;

const pipelineSteps = [
  { state: "triaged", label: "Triage" },
  { state: "patched", label: "Patch proposal" },
  { state: "reviewed", label: "Adversarial review" },
  { state: "validating", label: "Fixture checks" },
  { state: "awaiting_human", label: "Human review" },
  { state: "approved", label: "Approval recorded" },
] as const;

let currentRun: RemediationRun | undefined;
const startButton = document.querySelector<HTMLButtonElement>("#start-run")!;
const approveButton = document.querySelector<HTMLButtonElement>("#approve-run")!;
const runTitle = document.querySelector<HTMLHeadingElement>("#run-title")!;
const runState = document.querySelector<HTMLSpanElement>("#run-state")!;
const pipeline = document.querySelector<HTMLDivElement>("#pipeline")!;
const evidence = document.querySelector<HTMLDivElement>("#evidence")!;
const attempts = document.querySelector<HTMLSpanElement>("#attempts")!;
const actionNote = document.querySelector<HTMLParagraphElement>("#action-note")!;
const scenarioSelect = document.querySelector<HTMLSelectElement>("#scenario-select")!;
const scenarioHelp = document.querySelector<HTMLElement>("#scenario-help")!;
const exceptionBox = document.querySelector<HTMLDivElement>("#exception-box")!;
const exceptionReason = document.querySelector<HTMLTextAreaElement>("#exception-reason")!;

const scenarioDescriptions: Record<DemoScenario, string> = {
  standard: "Fixture agents produce a safe patch and pass the checks.",
  recoverable: "The first patch is intentionally unsafe. Review and checks should trigger one repair retry.",
  persistent: "Every proposed patch is intentionally unsafe. The retry limit should block approval and escalate to a human.",
};

scenarioSelect.addEventListener("change", () => {
  demoScenario = scenarioSelect.value as DemoScenario;
  scenarioHelp.textContent = scenarioDescriptions[demoScenario];
});

function renderRun(run?: RemediationRun) {
  if (!run) {
    pipeline.innerHTML = pipelineSteps.map((step, index) => `
      <div class="step"><span class="step-index">0${index + 1}</span><strong>${step.label}</strong><span class="step-status">Waiting</span></div>
    `).join("");
    return;
  }

  const eventStates = new Set(run.events.map((event) => event.state));
  pipeline.innerHTML = pipelineSteps.map((step, index) => {
    const complete = eventStates.has(step.state) || (step.state === "awaiting_human" && run.state === "approved");
    const status = complete ? "Complete" : run.state === "blocked" ? "Stopped" : "Pending";
    return `<div class="step ${complete ? "complete" : ""}"><span class="step-index">0${index + 1}</span><strong>${step.label}</strong><span class="step-status">${status}</span></div>`;
  }).join("");

  runTitle.textContent = run.state === "blocked" ? "Needs human investigation" : "SQL injection demo";
  runState.textContent = run.state.replaceAll("_", " ");
  runState.className = `state-badge ${run.state === "blocked" ? "blocked" : run.state === "approved" ? "approved" : "ready"}`;
  attempts.textContent = `${run.repairAttempts} repair retries`;
  exceptionBox.hidden = run.state !== "blocked";
  approveButton.disabled = run.state === "awaiting_human"
    ? false
    : run.state === "blocked"
      ? exceptionReason.value.trim().length === 0
      : true;
  approveButton.textContent = run.state === "approved"
    ? "Approval recorded"
    : run.state === "blocked"
      ? "Approve with exception"
      : "Approve demo patch";
  actionNote.textContent = run.state === "awaiting_human"
    ? "Review the diff and evidence before recording approval. This action stays in the browser."
    : run.state === "blocked"
      ? "The evidence gate is blocked. A human can record an exception approval with a required reason."
      : "Approval records a decision in this page only. It does not merge or deploy code.";

  const evidenceHtml = run.evidence.map((item) => {
    const badge = item.passed === true ? "PASS" : item.passed === false ? "REVIEW" : "RECORDED";
    const badgeClass = item.passed === true ? "pass" : item.passed === false ? "fail" : "neutral";
    return `<li class="evidence-item"><span class="result ${badgeClass}">${badge}</span><div><strong>${escapeHtml(item.producer)}</strong><p>${escapeHtml(item.summary)}</p><small>${escapeHtml(new Date(item.recordedAt).toLocaleTimeString())}</small></div></li>`;
  }).join("");
  const triageHtml = run.triage ? `<div class="result-card"><div class="section-head"><strong>Triage</strong><span class="muted small">${Math.round(run.triage.confidence * 100)}% fixture confidence</span></div><p>${escapeHtml(run.triage.summary)}</p></div>` : "";
  const findingsHtml = run.reviewFindings.length
    ? `<div class="result-card"><strong>Reviewer findings</strong><ul>${run.reviewFindings.map((finding) => `<li>${escapeHtml(finding.severity.toUpperCase())}: ${escapeHtml(finding.title)} — ${escapeHtml(finding.detail)}</li>`).join("")}</ul></div>`
    : `<div class="result-card"><strong>Adversarial review</strong><p>No blocking findings in the seeded review.</p></div>`;
  const checksHtml = run.checks.map((check) => `<div class="check-row"><span class="check-icon ${check.passed ? "pass" : "fail"}">${check.passed ? "✓" : "!"}</span><div><strong>${escapeHtml(check.name)}</strong><p>${escapeHtml(check.summary)}</p>${check.details ? `<small>${escapeHtml(check.details)}</small>` : ""}</div></div>`).join("");
  const diffHtml = run.patch ? `<div class="result-card"><div class="section-head"><strong>Proposed diff</strong><span class="muted small">${escapeHtml(run.patch.changedFiles.join(", "))}</span></div><pre class="diff">${escapeHtml(run.patch.diff)}</pre><p class="muted">${escapeHtml(run.patch.rationale)}</p></div>` : "";
  const eventHtml = `<details class="event-details"><summary>Run timeline (${run.events.length} events)</summary><ol>${run.events.map((event) => `<li><strong>${escapeHtml(event.state.replaceAll("_", " "))}</strong><span>${escapeHtml(event.message)}</span></li>`).join("")}</ol></details>`;
  evidence.innerHTML = `${triageHtml}${findingsHtml}<div class="result-card"><strong>Recorded evidence</strong><ul class="evidence-list">${evidenceHtml}</ul></div><div class="result-card"><strong>Deterministic fixture checks</strong>${checksHtml || "<p>No check output.</p>"}</div>${diffHtml}${eventHtml}`;
}

renderRun();

exceptionReason.addEventListener("input", () => {
  if (currentRun?.state === "blocked") {
    approveButton.disabled = exceptionReason.value.trim().length === 0;
  }
});

startButton.addEventListener("click", async () => {
  startButton.disabled = true;
  scenarioSelect.disabled = true;
  approveButton.disabled = true;
  exceptionBox.hidden = true;
  exceptionReason.value = "";
  startButton.textContent = "Running fixture agents…";
  runState.textContent = "running";
  runState.className = "state-badge running";
  try {
    currentRun = await orchestrator.run(alert);
    renderRun(currentRun);
    startButton.textContent = "Run demo again";
  } catch (error) {
    runState.textContent = "error";
    runState.className = "state-badge blocked";
    evidence.textContent = error instanceof Error ? error.message : "The demo run failed.";
    startButton.textContent = "Retry demo";
  } finally {
    startButton.disabled = false;
    scenarioSelect.disabled = false;
  }
});

approveButton.addEventListener("click", () => {
  if (!currentRun) return;
  try {
    if (currentRun.state === "blocked") {
      orchestrator.approveWithException(currentRun, exceptionReason.value);
    } else {
      orchestrator.approve(currentRun);
    }
    renderRun(currentRun);
  } catch (error) {
    actionNote.textContent = error instanceof Error ? error.message : "Approval could not be recorded.";
  }
});
