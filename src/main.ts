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

interface VulnerabilityExample {
  alert: SecurityAlert;
  vulnerabilityClass: string;
  triageSummary: string;
  safeMarker: string;
  unsafeMarker: string;
  safeRationale: string;
  unsafeRationale: string;
  safeDiff: string[];
  unsafeDiff: string[];
  reviewTitle: string;
  reviewDetail: string;
  checkName: string;
}

const examples: VulnerabilityExample[] = [
  {
    alert: {
      id: "DEMO-SQLI-001", ruleId: "PATCHFORGE-SQLI-001", title: "SQL injection in user lookup",
      severity: "high", repository: "demo/unsafe-users-api", commit: "fixture-a84d12c",
      filePath: "src/users.ts", line: 42, description: "User supplied email is concatenated into a SQL query.",
    },
    vulnerabilityClass: "SQL injection", triageSummary: "The user lookup builds a SQL statement with interpolated input. A parameterized query is the narrowest fix.",
    safeMarker: "db.query(query, [email])", unsafeMarker: "email = '${email}'",
    safeRationale: "Bind the email value as a query parameter so it is treated as data.",
    unsafeRationale: "Simulated flawed attempt: the user value is still interpolated into SQL.",
    safeDiff: [
      "diff --git a/src/users.ts b/src/users.ts", "--- a/src/users.ts", "+++ b/src/users.ts",
      "@@ -40,2 +40,2 @@ export async function findUser(email: string) {",
      "-  const query = `SELECT * FROM users WHERE email = '${email}'`;", "-  return db.query(query);",
      "+  const query = \"SELECT * FROM users WHERE email = ?\";", "+  return db.query(query, [email]);",
    ],
    unsafeDiff: [
      "diff --git a/src/users.ts b/src/users.ts", "--- a/src/users.ts", "+++ b/src/users.ts",
      "@@ -40,2 +40,2 @@ export async function findUser(email: string) {",
      "+  const query = `SELECT * FROM users WHERE email = '${email}'`;", "+  return db.query(query);",
    ],
    reviewTitle: "User input may still be interpolated", reviewDetail: "The proposed diff must bind the email as a query parameter.",
    checkName: "SQL injection pattern fixture",
  },
  {
    alert: {
      id: "DEMO-XSS-001", ruleId: "PATCHFORGE-XSS-001", title: "Reflected XSS in search preview",
      severity: "high", repository: "demo/unsafe-search-ui", commit: "fixture-51c2b70",
      filePath: "src/search.ts", line: 18, description: "A search term is inserted into an HTML preview without safe text handling.",
    },
    vulnerabilityClass: "Cross-site scripting (XSS)", triageSummary: "The search preview treats user input as markup. Render the value as text so the browser does not parse it as HTML.",
    safeMarker: "preview.textContent = searchTerm", unsafeMarker: "preview.innerHTML = searchTerm",
    safeRationale: "Use the DOM text API so user supplied text is rendered as data, not markup.",
    unsafeRationale: "Simulated flawed attempt: user supplied text is still assigned as HTML.",
    safeDiff: [
      "diff --git a/src/search.ts b/src/search.ts", "--- a/src/search.ts", "+++ b/src/search.ts",
      "@@ -16,1 +16,1 @@ export function renderPreview(searchTerm: string) {",
      "-  preview.innerHTML = searchTerm;", "+  preview.textContent = searchTerm;",
    ],
    unsafeDiff: [
      "diff --git a/src/search.ts b/src/search.ts", "--- a/src/search.ts", "+++ b/src/search.ts",
      "@@ -16,1 +16,1 @@ export function renderPreview(searchTerm: string) {",
      "+  preview.innerHTML = searchTerm;",
    ],
    reviewTitle: "Untrusted input is still parsed as HTML", reviewDetail: "The proposed diff should render the search value as text rather than assigning it to innerHTML.",
    checkName: "XSS output encoding fixture",
  },
  {
    alert: {
      id: "DEMO-SECRET-001", ruleId: "PATCHFORGE-SECRET-001", title: "Credential committed in deployment config",
      severity: "critical", repository: "demo/unsafe-deploy-config", commit: "fixture-9e482a1",
      filePath: "src/cloudConfig.ts", line: 7, description: "A synthetic static credential is present in tracked application configuration.",
    },
    vulnerabilityClass: "Hardcoded secret", triageSummary: "A credential-like value is stored in tracked configuration. Read it from the runtime secret store and rotate any real exposed credential.",
    safeMarker: 'secrets.get("cloud/access-key")', unsafeMarker: "STATIC_FIXTURE_CREDENTIAL",
    safeRationale: "Remove the synthetic literal and read the credential from the runtime secret store; rotate any real exposed key.",
    unsafeRationale: "Simulated flawed attempt: a static credential remains in tracked configuration.",
    safeDiff: [
      "diff --git a/src/cloudConfig.ts b/src/cloudConfig.ts", "--- a/src/cloudConfig.ts", "+++ b/src/cloudConfig.ts",
      "@@ -7,1 +7,1 @@ cloud configuration", '-const CLOUD_ACCESS_KEY = "STATIC_FIXTURE_CREDENTIAL";',
      '+const CLOUD_ACCESS_KEY = secrets.get("cloud/access-key");',
    ],
    unsafeDiff: [
      "diff --git a/src/cloudConfig.ts b/src/cloudConfig.ts", "--- a/src/cloudConfig.ts", "+++ b/src/cloudConfig.ts",
      "@@ -7,1 +7,1 @@ cloud configuration", '+const CLOUD_ACCESS_KEY = "STATIC_FIXTURE_CREDENTIAL";',
    ],
    reviewTitle: "Static credential remains in the change", reviewDetail: "The proposed diff should remove the tracked credential and refer to the runtime secret store.",
    checkName: "Secret removal fixture",
  },
  {
    alert: {
      id: "DEMO-DEP-001", ruleId: "PATCHFORGE-DEP-001", title: "Vulnerable authentication dependency",
      severity: "high", repository: "demo/unsafe-auth-service", commit: "fixture-36ad882",
      filePath: "package.json", line: 24, description: "The fixture advisory marks demo-auth 1.4.2 as vulnerable; 2.1.0 is the simulated fixed release.",
    },
    vulnerabilityClass: "Vulnerable dependency", triageSummary: "The manifest pins demo-auth to a fixture version affected by an advisory. Upgrade to the simulated fixed release and rerun dependency checks.",
    safeMarker: '"demo-auth": "2.1.0"', unsafeMarker: '"demo-auth": "1.4.2"',
    safeRationale: "Upgrade demo-auth to the fixture's fixed release and recheck the dependency advisory.",
    unsafeRationale: "Simulated flawed attempt: the manifest still selects the vulnerable fixture release.",
    safeDiff: [
      "diff --git a/package.json b/package.json", "--- a/package.json", "+++ b/package.json",
      "@@ -24,1 +24,1 @@ dependencies", '-  "demo-auth": "1.4.2",', '+  "demo-auth": "2.1.0",',
    ],
    unsafeDiff: [
      "diff --git a/package.json b/package.json", "--- a/package.json", "+++ b/package.json",
      "@@ -24,1 +24,1 @@ dependencies", '+  "demo-auth": "1.4.2",',
    ],
    reviewTitle: "Vulnerable dependency version remains", reviewDetail: "The proposed manifest change should select the simulated fixed release.",
    checkName: "Dependency advisory fixture",
  },
];
let selectedAlert = examples[0].alert;
const profileFor = (alert: SecurityAlert) => examples.find((example) => example.alert.id === alert.id) ?? examples[0];
const HISTORY_KEY = "patchforge.run-history.v1";
const HISTORY_LIMIT = 20;

function loadRunHistory(): RemediationRun[] {
  try {
    const saved: unknown = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]");
    if (!Array.isArray(saved)) return [];
    return saved.filter((item): item is RemediationRun =>
      !!item && typeof item === "object" && typeof item.id === "string" &&
      typeof item.state === "string" && item.alert && Array.isArray(item.evidence) &&
      Array.isArray(item.events) && Array.isArray(item.checks) && Array.isArray(item.reviewFindings),
    ).slice(0, HISTORY_LIMIT);
  } catch {
    return [];
  }
}

let runHistory = loadRunHistory();

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
type DemoScenario = "standard" | "recoverable" | "persistent";
let demoScenario: DemoScenario = "standard";

const triageAgent: TriageAgent = {
  async triage(alert) {
    await sleep(260);
    const profile = profileFor(alert);
    return {
      vulnerabilityClass: profile.vulnerabilityClass,
      summary: profile.triageSummary,
      affectedFiles: [alert.filePath],
      complexity: "low",
      confidence: 0.96,
    };
  },
};

const repairAgent: RepairAgent = {
  async propose(alert, _triage, feedback): Promise<Patch> {
    await sleep(320);
    const profile = profileFor(alert);
    const safePatch = demoScenario === "standard" || (demoScenario === "recoverable" && feedback.length > 0);
    return {
      changedFiles: [alert.filePath],
      rationale: safePatch ? profile.safeRationale : profile.unsafeRationale,
      diff: (safePatch ? profile.safeDiff : profile.unsafeDiff).join("\n"),
    };
  },
};

const adversarialReviewer: AdversarialReviewer = {
  async review(alert, patch) {
    await sleep(260);
    const profile = profileFor(alert);
    const additions = patch.diff.split("\n").filter((line) => line.startsWith("+") && !line.startsWith("+++"));
    const addedText = additions.join("\n");
    const safePatch = addedText.includes(profile.safeMarker) && !addedText.includes(profile.unsafeMarker);
    return safePatch ? [] : [{
      severity: "high",
      title: profile.reviewTitle,
      detail: profile.reviewDetail,
      filePath: alert.filePath,
    }];
  },
};

const validator: Validator = {
  async validate(alert, patch): Promise<CheckResult[]> {
    await sleep(320);
    const profile = profileFor(alert);
    const additions = patch.diff.split("\n").filter((line) => line.startsWith("+") && !line.startsWith("+++"));
    const addedText = additions.join("\n");
    const safePatternPresent = addedText.includes(profile.safeMarker);
    const unsafePatternAbsent = !addedText.includes(profile.unsafeMarker);
    const fixturePassed = safePatternPresent && unsafePatternAbsent;
    return [
      {
        name: profile.checkName,
        passed: fixturePassed,
        summary: fixturePassed ? "The simulated patch contains the expected remediation and omits the unsafe pattern." : "The patch did not satisfy the fixture's remediation markers.",
        details: "Deterministic diff inspection only; this does not run the target application or a real security scanner.",
      },
      {
        name: "Adversarial patch assertions",
        passed: safePatternPresent && unsafePatternAbsent,
        summary: safePatternPresent && unsafePatternAbsent ? "Expected safe marker found; unsafe marker absent from added lines." : "Expected safe marker missing or unsafe marker remains in added lines.",
        details: `Fixture vulnerability class: ${profile.vulnerabilityClass}. No exploit or target code is executed.`,
      },
      {
        name: "Demo workflow assertions",
        passed: fixturePassed,
        summary: fixturePassed ? "All seeded demo assertions passed." : "One or more seeded demo assertions failed.",
        details: "These are deterministic diff fixtures, not repository tests or a security scan.",
      },
    ];
  },
};

let currentRun: RemediationRun | undefined;

const orchestrator = new RemediationOrchestrator({
  triageAgent,
  repairAgent,
  reviewer: adversarialReviewer,
  validator,
  maxRepairAttempts: 3,
  onProgress: (run) => {
    currentRun = run;
    renderRun(run);
  },
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
        <p class="intro">Choose a seeded security alert and run it through triage, repair, independent review, and deterministic fixture checks. Inspect the evidence, then record a human approval.</p>
      </section>
      <section class="workspace">
        <aside class="column">
          <article class="panel alert-panel">
            <div class="section-head"><span class="overline">Seeded alert</span><span id="alert-severity" class="severity">HIGH</span></div>
            <label class="scenario-control alert-picker" for="alert-select">Vulnerability example
              <select id="alert-select">${examples.map((example) => `<option value="${escapeHtml(example.alert.id)}">${escapeHtml(profileFor(example.alert).vulnerabilityClass)}</option>`).join("")}</select>
            </label>
            <h2 id="alert-title"></h2>
            <p id="alert-description" class="muted"></p>
            <dl class="facts">
              <div><dt>Repository</dt><dd id="alert-repository"></dd></div>
              <div><dt>Location</dt><dd id="alert-location"></dd></div>
              <div><dt>Rule</dt><dd id="alert-rule"></dd></div>
            </dl>
          </article>
          <article class="panel safety-note">
            <span class="overline">Demo boundaries</span>
            <p>All vulnerability examples use fixture agents and diff-marker checks. Nothing connects to a repository, executes an exploit, or runs a real security scan.</p>
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
            <div id="pipeline" class="pipeline" aria-label="Six-step remediation workflow" aria-live="polite"></div>
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
            <div class="history-tools">
              <label for="run-history">Recent runs</label>
              <select id="run-history" aria-label="Open a saved remediation run">
                <option value="">No saved runs yet</option>
              </select>
              <button id="export-evidence" class="button secondary" type="button" disabled>Export evidence JSON</button>
              <small id="history-status">Run history is stored in this browser only.</small>
            </div>
          </article>
          <article class="panel evidence-panel">
            <div class="section-head"><span class="overline">Evidence trail</span><span id="attempts" class="muted small"></span></div>
            <div id="evidence" class="empty-state">Start the demo to see triage notes, review results, checks, and the proposed diff.</div>
          </article>
        </section>
      </section>
      <footer>PatchForge prototype · demo run history is stored in this browser only</footer>
    </main>
  </div>
`;

const pipelineSteps = [
  { state: "triaged", label: "Understand the alert", description: "Classify the issue and locate affected code." },
  { state: "patched", label: "Draft a fix", description: "Propose a focused change for this vulnerability." },
  { state: "reviewed", label: "Challenge the fix", description: "An independent reviewer looks for weaknesses." },
  { state: "validating", label: "Run safety checks", description: "Fixture checks inspect the patch for expected changes." },
  { state: "awaiting_human", label: "Review the evidence", description: "You inspect the diff, findings, and check results." },
  { state: "approved", label: "Record your decision", description: "Approval is saved in the local audit trail." },
] as const;

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
const historySelect = document.querySelector<HTMLSelectElement>("#run-history")!;
const exportButton = document.querySelector<HTMLButtonElement>("#export-evidence")!;
const historyStatus = document.querySelector<HTMLElement>("#history-status")!;
const alertSelect = document.querySelector<HTMLSelectElement>("#alert-select")!;
const alertSeverity = document.querySelector<HTMLElement>("#alert-severity")!;
const alertTitle = document.querySelector<HTMLHeadingElement>("#alert-title")!;
const alertDescription = document.querySelector<HTMLParagraphElement>("#alert-description")!;
const alertRepository = document.querySelector<HTMLElement>("#alert-repository")!;
const alertLocation = document.querySelector<HTMLElement>("#alert-location")!;
const alertRule = document.querySelector<HTMLElement>("#alert-rule")!;

function renderPipeline(run?: RemediationRun) {
  const eventStates = new Set(run?.events.map((event) => event.state) ?? []);
  const stateIndex: Partial<Record<RemediationRun["state"], number>> = {
    received: 0, triaged: 1, patched: 2, repairing: 1, reviewed: 3,
    validating: 3, awaiting_human: 4, approved: 5, blocked: 3,
  };
  const activeIndex = run ? stateIndex[run.state] ?? 0 : -1;
  pipeline.innerHTML = pipelineSteps.map((step, index) => {
    const blocked = run?.state === "blocked" && index === 3;
    const held = run?.state === "blocked" && index > 3;
    const complete = run?.state === "approved" || (
      !!run && index < activeIndex && eventStates.has(step.state)
    );
    const active = !!run && !complete && !blocked && !held && index === activeIndex;
    const status = !run ? "Waiting"
      : blocked ? "Needs attention"
        : held ? "On hold"
          : run.state === "approved" && index === 5 ? "Recorded"
            : run.state === "awaiting_human" && index === 4 ? "Your turn"
              : complete ? "Complete"
                : active ? "In progress"
                  : "Up next";
    const classes = ["step", complete ? "complete" : "", active ? "current" : "", blocked ? "needs-attention" : "", held ? "on-hold" : ""].filter(Boolean).join(" ");
    return `<div class="${classes}"${active ? ' aria-current="step"' : ""}>
      <span class="step-index">STEP ${index + 1}</span>
      <strong>${step.label}</strong>
      <p class="step-description">${step.description}</p>
      <span class="step-status">${status}</span>
    </div>`;
  }).join("");
}

function renderAlert(alert: SecurityAlert) {
  alertSeverity.textContent = alert.severity;
  alertTitle.textContent = alert.title;
  alertDescription.textContent = alert.description;
  alertRepository.textContent = alert.repository;
  alertLocation.textContent = `${alert.filePath}:${alert.line}`;
  alertRule.textContent = alert.ruleId;
}

function renderHistory() {
  const selectedId = currentRun?.id ?? "";
  historySelect.innerHTML = runHistory.length
    ? `<option value="">Select a saved run…</option>${runHistory.map((run) => {
      const date = new Date(run.events.at(-1)?.recordedAt ?? Date.now()).toLocaleString();
      return `<option value="${escapeHtml(run.id)}">${escapeHtml(run.alert.title)} · ${escapeHtml(run.state.replaceAll("_", " "))} · ${escapeHtml(date)}</option>`;
    }).join("")}`
    : `<option value="">No saved runs yet</option>`;
  historySelect.value = selectedId;
  exportButton.disabled = !currentRun;
}

function saveRun(run: RemediationRun) {
  runHistory = [run, ...runHistory.filter((item) => item.id !== run.id)].slice(0, HISTORY_LIMIT);
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(runHistory));
    historyStatus.textContent = `Saved locally · ${runHistory.length} of ${HISTORY_LIMIT} recent runs`;
  } catch {
    historyStatus.textContent = "Browser storage is unavailable. Export this run to keep its evidence.";
  }
  renderHistory();
}

function exportCurrentRun() {
  if (!currentRun) return;
  const bundle = {
    format: "patchforge-evidence-v1",
    exportedAt: new Date().toISOString(),
    limitations: "Client-side demo fixture only. This bundle does not prove system security and contains no live repository or scanner results.",
    run: currentRun,
  };
  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `patchforge-evidence-${currentRun.id.replace(/[^a-zA-Z0-9_-]/g, "_")}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

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
    renderPipeline();
    runTitle.textContent = "Ready to start";
    runState.textContent = "Not started";
    runState.className = "state-badge";
    attempts.textContent = "";
    approveButton.disabled = true;
    approveButton.textContent = "Approve demo patch";
    exceptionBox.hidden = true;
    actionNote.textContent = "Approval records a decision in this page only. It does not merge or deploy code.";
    evidence.textContent = "Start the demo to see triage notes, review results, checks, and the proposed diff.";
    renderHistory();
    return;
  }

  renderPipeline(run);

  runTitle.textContent = run.state === "blocked" ? "Needs human investigation" : run.alert.title;
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
  renderHistory();
}

renderRun();
renderHistory();

historySelect.addEventListener("change", () => {
  const selected = runHistory.find((run) => run.id === historySelect.value);
  if (!selected) return;
  currentRun = selected;
  selectedAlert = selected.alert;
  alertSelect.value = selectedAlert.id;
  renderAlert(selectedAlert);
  exceptionReason.value = "";
  renderRun(currentRun);
  startButton.textContent = "Run demo again";
});

alertSelect.addEventListener("change", () => {
  const example = examples.find((item) => item.alert.id === alertSelect.value);
  if (!example) return;
  selectedAlert = example.alert;
  exceptionReason.value = "";
  renderAlert(selectedAlert);
  currentRun = undefined;
  renderRun();
  startButton.textContent = "Start demo run";
});

exportButton.addEventListener("click", exportCurrentRun);

exceptionReason.addEventListener("input", () => {
  if (currentRun?.state === "blocked") {
    approveButton.disabled = exceptionReason.value.trim().length === 0;
  }
});

startButton.addEventListener("click", async () => {
  startButton.disabled = true;
  scenarioSelect.disabled = true;
  alertSelect.disabled = true;
  historySelect.disabled = true;
  exportButton.disabled = true;
  approveButton.disabled = true;
  currentRun = undefined;
  renderHistory();
  evidence.textContent = "Running the selected fixture scenario…";
  exceptionBox.hidden = true;
  exceptionReason.value = "";
  startButton.textContent = "Running fixture agents…";
  runState.textContent = "running";
  runState.className = "state-badge running";
  try {
    currentRun = await orchestrator.run(selectedAlert);
    saveRun(currentRun);
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
    alertSelect.disabled = false;
    historySelect.disabled = false;
    renderHistory();
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
    saveRun(currentRun);
    renderRun(currentRun);
  } catch (error) {
    actionNote.textContent = error instanceof Error ? error.message : "Approval could not be recorded.";
  }
});
