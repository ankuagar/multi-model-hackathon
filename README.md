# PatchForge

PatchForge is a human-gated security remediation prototype built for Base44.
It demonstrates a multi-agent workflow: a triage model classifies an alert, a
repair model proposes a patch, an independent model challenges it, deterministic
checks examine the diff, and a person reviews the evidence before recording an
approval.

## Two run modes

- **Fixture agents** are a guided, free demo for SQL injection, reflected XSS,
  hardcoded secrets, and vulnerable dependencies. They do not connect to a
  repository, execute code or exploits, or run a real scanner.
- **OpenRouter live agents** call the backend function in
  `base44/functions/patchforge-agent/`. Four distinct OpenRouter models handle
  triage, simple repair, complex repair, and review. The triage result routes
  repair to the simple or complex model. Default model IDs use OpenRouter free
  endpoints; they can be overridden with Base44 application secrets. Usage is
  subject to OpenRouter and upstream provider limits.

Live mode currently sends only the selected alert metadata to the models. It
does not fetch a repository checkout or source code. The repair role is
instructed to avoid inventing code without source context; a human must still
check whether any proposed diff applies. Its deterministic checks validate
diff structure only. No tests, scanner, exploit attempt, pull request, merge, or
deployment is performed. Approval records a decision in this browser's local
evidence history.

## Base44 setup

1. Install the SDK dependency and update the lockfile:

   ```sh
   npm install
   ```

2. Enable password login for the app if it is not already enabled:

   ```sh
   npx base44 auth password-login enable
   ```

   Deploying `base44/auth/` configuration is included in a full deploy. You can
   also use an already enabled Base44 social login from the SDK if desired.

3. In Base44 **Application Secrets**, add `OPENROUTER_API_KEY` with your
   OpenRouter API key. Never put this key in frontend code or commit it.

   The backend defaults to four distinct OpenRouter free models. To change them,
   optionally set these secrets to model IDs from OpenRouter's catalog:

   ```text
   PATCHFORGE_TRIAGE_MODEL=<model id>
   PATCHFORGE_SIMPLE_REPAIR_MODEL=<model id>
   PATCHFORGE_COMPLEX_REPAIR_MODEL=<model id>
   PATCHFORGE_REVIEW_MODEL=<model id>
   ```

   Keep all four model IDs different. A live workflow makes one triage call,
   one review call, and at least one repair call; repair retries make more
   calls. Free model availability and provider rate limits can change.

4. Deploy the site and backend function together:

   ```sh
   npx base44 deploy --build
   ```

   `base44 site deploy --build` deploys the static site only and will not publish
   the agent function.

## Local development

```sh
npm run typecheck
npm run dev
```

The workflow contract is in [`src/workflow.ts`](src/workflow.ts), the UI and
fixture agents are in [`src/main.ts`](src/main.ts), and the OpenRouter adapter
is in [`base44/functions/patchforge-agent/entry.ts`](base44/functions/patchforge-agent/entry.ts).
