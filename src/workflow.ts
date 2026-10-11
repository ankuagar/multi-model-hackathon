/** Provider-neutral workflow contract for a human-gated security remediation. */

export type RunState =
  | "received" | "triaged" | "patched" | "reviewed" | "validating"
  | "repairing" | "awaiting_human" | "blocked" | "approved";
export type Severity = "low" | "medium" | "high" | "critical";

export interface SecurityAlert {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  repository: string;
  commit: string;
  filePath: string;
  line: number;
  description: string;
}
export interface Triage {
  vulnerabilityClass: string;
  summary: string;
  affectedFiles: string[];
  complexity: "low" | "medium" | "high";
  confidence: number;
}
export interface Patch { diff: string; changedFiles: string[]; rationale: string }
export interface ReviewFinding {
  severity: Severity;
  title: string;
  detail: string;
  filePath?: string;
  line?: number;
}
export interface CheckResult {
  name: string;
  passed: boolean;
  summary: string;
  details?: string;
}
export interface Evidence {
  kind: "triage" | "patch" | "adversarial_review" | "check" | "pull_request";
  producer: string;
  summary: string;
  passed?: boolean;
  artifact?: string;
  recordedAt: string;
}
export interface RunEvent { state: RunState; message: string; recordedAt: string }
export interface RemediationRun {
  id: string;
  alert: SecurityAlert;
  state: RunState;
  triage?: Triage;
  patch?: Patch;
  reviewFindings: ReviewFinding[];
  checks: CheckResult[];
  evidence: Evidence[];
  events: RunEvent[];
  repairAttempts: number;
  maxRepairAttempts: number;
  pullRequestUrl?: string;
}

export interface TriageAgent { triage(alert: SecurityAlert): Promise<Triage> }
export interface RepairAgent {
  propose(alert: SecurityAlert, triage: Triage, feedback: string[]): Promise<Patch>
}
export interface AdversarialReviewer {
  review(alert: SecurityAlert, patch: Patch): Promise<ReviewFinding[]>
}
export interface Validator {
  validate(alert: SecurityAlert, patch: Patch): Promise<CheckResult[]>
}
export interface PullRequestPublisher { prepare(run: RemediationRun): Promise<string> }

export interface OrchestratorOptions {
  triageAgent: TriageAgent;
  repairAgent: RepairAgent;
  reviewer: AdversarialReviewer;
  validator: Validator;
  publisher?: PullRequestPublisher;
  maxRepairAttempts?: number;
  createRunId?: () => string;
  now?: () => string;
}

const BLOCKING_SEVERITIES = new Set<Severity>(["high", "critical"]);

/** Coordinates the workflow; it never merges or deploys a patch. */
export class RemediationOrchestrator {
  private readonly now: () => string;
  private readonly createRunId: () => string;
  private readonly maxRepairAttempts: number;

  constructor(private readonly options: OrchestratorOptions) {
    this.now = options.now ?? (() => new Date().toISOString());
    this.createRunId = options.createRunId ?? (() => crypto.randomUUID());
    this.maxRepairAttempts = options.maxRepairAttempts ?? 3;
    if (!Number.isInteger(this.maxRepairAttempts) || this.maxRepairAttempts < 0) {
      throw new Error("maxRepairAttempts must be a non-negative integer");
    }
  }

  async run(alert: SecurityAlert): Promise<RemediationRun> {
    const run: RemediationRun = {
      id: this.createRunId(), alert, state: "received", reviewFindings: [],
      checks: [], evidence: [], events: [], repairAttempts: 0,
      maxRepairAttempts: this.maxRepairAttempts,
    };

    run.triage = await this.options.triageAgent.triage(alert);
    this.addEvidence(run, { kind: "triage", producer: "triage_agent", summary: run.triage.summary });
    this.transition(run, "triaged", "Alert classified and affected files identified");

    let feedback: string[] = [];
    while (true) {
      run.patch = await this.options.repairAgent.propose(alert, run.triage, feedback);
      this.addEvidence(run, {
        kind: "patch", producer: "repair_agent", summary: run.patch.rationale,
        artifact: run.patch.diff,
      });
      this.transition(run, "patched", "Patch proposal recorded");

      run.reviewFindings = await this.options.reviewer.review(alert, run.patch);
      const blockingFindings = run.reviewFindings.filter((finding) =>
        BLOCKING_SEVERITIES.has(finding.severity),
      );
      this.addEvidence(run, {
        kind: "adversarial_review", producer: "adversarial_reviewer",
        summary: `${run.reviewFindings.length} finding(s)`, passed: blockingFindings.length === 0,
      });
      this.transition(run, "reviewed", "Independent patch review completed");

      this.transition(run, "validating", "Deterministic validation started");
      run.checks = await this.options.validator.validate(alert, run.patch);
      for (const check of run.checks) {
        this.addEvidence(run, {
          kind: "check", producer: check.name, summary: check.summary, passed: check.passed,
        });
      }

      // An empty check set is not evidence that validation passed.
      const checksPassed = run.checks.length > 0 && run.checks.every((check) => check.passed);
      if (blockingFindings.length === 0 && checksPassed) {
        if (this.options.publisher) {
          run.pullRequestUrl = await this.options.publisher.prepare(run);
          this.addEvidence(run, {
            kind: "pull_request", producer: "repository_adapter",
            summary: "Pull request prepared for human review", artifact: run.pullRequestUrl,
          });
        }
        this.transition(run, "awaiting_human", "Evidence gates passed; human approval is required");
        return run;
      }

      if (run.repairAttempts >= run.maxRepairAttempts) {
        this.transition(run, "blocked", "Repair limit reached; human investigation required");
        return run;
      }
      feedback = blockingFindings.map(
        (finding) => `Review finding: ${finding.title}: ${finding.detail}`,
      );
      feedback.push(...run.checks.filter((check) => !check.passed).map(
        (check) => `Check failed (${check.name}): ${check.summary}\n${check.details ?? ""}`,
      ));
      if (run.checks.length === 0) {
        feedback.push("Validation returned no checks; provide deterministic validation evidence.");
      }
      run.repairAttempts += 1;
      this.transition(run, "repairing", `Returning evidence to repair agent (attempt ${run.repairAttempts})`);
    }
  }

  /** Records human approval. Repository merge and deployment remain separate actions. */
  approve(run: RemediationRun): void {
    if (run.state !== "awaiting_human") {
      throw new Error("Only a run awaiting human review can be approved");
    }
    this.transition(run, "approved", "Human reviewer approved the remediation");
  }

  private transition(run: RemediationRun, state: RunState, message: string): void {
    run.state = state;
    run.events.push({ state, message, recordedAt: this.now() });
  }

  private addEvidence(run: RemediationRun, evidence: Omit<Evidence, "recordedAt">): void {
    run.evidence.push({ ...evidence, recordedAt: this.now() });
  }
}
