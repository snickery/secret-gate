# secret-gate

A GitHub/Forgejo Action that **fails a push or pull request that adds a committed secret**.
It scans only the lines the change *adds*, so it's fast on large repos and quiet about old
history. It never prints the secret it found.

## Use

```yaml
on: [push, pull_request]
jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }          # the diff base must be reachable
      - uses: snickery/secret-gate@v1
        with:
          base: ${{ github.event.pull_request.base.sha || github.event.before }}
          head: ${{ github.event.pull_request.head.sha || github.sha }}
          # exclude: ci/gate-test/fixtures/*   # optional: paths holding intentional fake secrets
```

On Forgejo the same workflow works from `.forgejo/workflows/`. The short `snickery/secret-gate@v1`
form resolves through the instance's `DEFAULT_ACTIONS_URL` (GitHub by default).

## What it flags

- Private keys (`-----BEGIN … PRIVATE KEY-----`).
- Token formats: AWS (`AKIA…`), GitHub (`ghp_`/`gho_`/`ghs_`/`ghu_`, `github_pat_`), GitLab (`glpat-`),
  Slack (`xox…-`) and JWTs.
- A **literal, high-entropy value under a secret-named key**: `password`, `secret`, `api_key`,
  `access_token`, `client_secret`, `bearer` and their variants, written as `key = value` or `key: value`.

What it deliberately lets through, because these are references rather than secrets:
`${VAR}`, `$VAR`, `EnvironmentFile=`, `*_FILE=`, `!ENV` / `!secret` tags, paths, short values,
plain words and placeholders (`changeme`, `example`, `your_…`, `<…>`, `xxxx`, …).

A known false positive can stay with a trailing `# security-gate:allow` on the line.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | clean |
| 1 | a possible secret was added. The log names the file and, for `key = value` lines, the key, never the value |
| 2 | the scanner itself failed: not a repo, an unreachable commit, or a failed self-test. **It never reports clean when it couldn't scan** |

Before every scan it runs three canaries: a known secret must be flagged, a known-clean line must
pass, and the line reader must return what it was given. If any of them fails, it exits 2.

## Run it locally

```bash
bash secret-gate.sh <base> <head>        # e.g. origin/main HEAD
```

It works on bash 3.2 (macOS) and bash 5. Tests: `bash ci/gate-test/run.sh`, the fixture corpus in
`ci/gate-test/fixtures/{block,pass}`.

MIT licensed.
