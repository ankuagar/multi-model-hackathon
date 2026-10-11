# PatchForge

PatchForge is a human-gated security remediation prototype targeting Base44.
The interactive demo includes seeded examples for SQL injection, reflected XSS,
hardcoded secrets, and vulnerable dependencies. Each alert runs through a
simulated triage agent, repair agent, adversarial reviewer, and deterministic
diff-marker checks. Users can choose a standard pass, a recoverable first attempt,
or a persistent failure that escalates for human investigation. The user can
inspect the proposed diff and record an approval when evidence gates pass. A
blocked run can only be approved through a separate human exception action with
a required reason, which is added to the evidence trail.
Run history persists in browser storage, and each selected run can be exported
as a JSON evidence bundle for review.

This is a client-side demo. Its agents and checks are fixtures: it does not
connect to a repository, execute SQL, run a real exploit, or perform a security
scan. History is local to the browser and can be cleared with its site data.
Approval does not merge or deploy code.

The workflow contract lives in [`src/workflow.ts`](src/workflow.ts), and the
interactive demo is in [`src/main.ts`](src/main.ts). Base44 settings live in
[`base44/config.jsonc`](base44/config.jsonc); the site builds to `dist/`.

## Local development

```sh
npm install
npm run typecheck
npm run dev
```

## Deploy updates to Base44

From a checkout linked to the PatchForge Base44 app:

```sh
base44 site deploy --build
```

If this is a fresh checkout, sign in and link it to the existing app before
deploying. The generated `base44/.app.jsonc` file is ignored by Git.
