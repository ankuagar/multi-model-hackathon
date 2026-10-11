# PatchForge

PatchForge is a human-gated security remediation starter targeting Base44. The
MVP will focus on a seeded SQL injection alert and record triage, patch
proposals, independent review, deterministic checks, and human approval.

The hosted preview is a static page in `public/`. The provider-neutral workflow
contract lives in [`src/workflow.ts`](src/workflow.ts): it defines bounded
repair attempts and a human approval gate, and never merges or deploys a patch.
No scanner, model, repository, or sandbox integration is connected yet.

## Base44 project

Base44 project settings are in [`base44/config.jsonc`](base44/config.jsonc).
The preview is configured as private. To deploy from this directory:

```sh
npm install
npm run typecheck
npm install --global base44
base44 login
base44 link --create --name patchforge-starter --description "Human-gated security remediation starter"
base44 site deploy --no-build
```

Base44's CLI login links the local checkout to an app in your Base44 workspace.
Keep the generated `base44/.app.jsonc` out of version control.
