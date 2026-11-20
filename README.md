# Idemcore Receipt Verify

A GitHub Action that checks [Idemcore](https://idemcore.net) receipts stored in your repository, on every push or pull request.

An Idemcore receipt is a signed record that ties an AI answer to the exact model and settings that produced it. This action confirms that each receipt is genuine and unchanged, so you can keep AI outputs in a repository and prove later that nobody edited them.

- **Free.** Verifying receipts never needs an API key or an account.
- **Offline.** Checks run inside the job. Nothing from your repository is uploaded.
- **Clear results.** A pass/fail table is written to the job summary, and the step fails when a receipt has been altered.

## Usage

```yaml
name: Check AI receipts

on:
  push:
  pull_request:

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Verify Idemcore receipts
        uses: idemcore/verify-action@v1
        with:
          path: "receipts/**/*.{json,jsonl,ndjson,log}"
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `**/*.{json,jsonl,ndjson,log}` | Glob, or comma-separated globs, relative to the workspace |
| `keys` | bundled Idemcore production public key | Path to a JWK, JWK array or JWKS file of keys you trust |
| `fail_on_error` | `true` | Fail the step when any check fails |
| `require_files` | `true` | Fail when the glob matches no checkable files |

## Outputs

| Output | Meaning |
|---|---|
| `passed` | Number of checks that passed |
| `failed` | Number of checks that failed |
| `checked` | Total number of checks |

## What it checks

- A signed receipt JSON (formats r1 and r2), or an object with a `receipt` field
- A file holding several receipts (a `receipts` array or object)
- An Idemcore audit export (`events`, `roots`, optional `receipts`): the event chain and the signed daily roots
- JSONL / NDJSON files with one of the objects above per line
- A public token log, checked against its receipt
- A public share link (`https://idemcore.net/...` or its share ID): the action downloads the public receipt and checks it. No API key is sent.

Other JSON files, such as `package.json`, are skipped, so the broad default glob is safe.

## Getting receipts

Receipts come with every answer from the Idemcore API, the SDKs and the integrations for n8n, Make, Zapier, MCP clients and more. Generating receipts needs an API key from [idemcore.net](https://idemcore.net) and is billed per token. Verifying them, with this action or any other Idemcore verifier, is always free.

## Development

```bash
npm install
npm test
npm run build   # rebuilds dist/index.mjs; commit it with your change
```

The test fixtures in `test/fixtures` are official public test vectors signed with an ephemeral test key. They are not live receipts.

## Support

dev@idemcore.net · MATEIAM COMPANY LIMITED, Ho Chi Minh City, Vietnam

## License

Apache-2.0
