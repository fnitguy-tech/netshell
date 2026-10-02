# PROJECT_NAME

**This is a template repository, not a real project.** It is the
starting skeleton I use for infrastructure-automation projects in my
home lab: a small role-pipeline pattern in plain Python (dry-run first,
per-host error isolation, explicit registry), OpenBao-first secrets
handling, gitignored inventories with checked-in examples, tests that
run offline, and runbook/architecture doc skeletons. To use it: click
**Use this template** on GitHub (or clone and re-init), then work
through `TEMPLATE_USAGE.md` before writing any real code.

One-sentence description of what this project provisions/deploys and
on what infrastructure (host class, FIPS mode or not, live or planning
stage).

**Building or operating this project? See
[`DEPLOYMENT_RUNBOOK.md`](DEPLOYMENT_RUNBOOK.md)** (dependency-ordered
build sequence, real gotchas from first live deployment) **and
[`OPERATIONS_RUNBOOK.md`](OPERATIONS_RUNBOOK.md)** (health checks,
maintenance, troubleshooting).

## What this does

Longer description: what problem this solves, why it exists, what it
deliberately does *not* do, and how it relates to other projects in the
lab if relevant (additive to an existing system? replacing something?
a dependency of something else?).

## Prerequisites

- Python 3.11+, `git`
- Anything this specific project needs: build tooling, sibling repos it
  checks out next to itself, credential files, infrastructure that must
  already exist and be reachable.
- See `docs/INFRASTRUCTURE_PREREQUISITES.md` for the full detail once
  this project has any.

## Setup and tests

```bash
pip install -r requirements.txt   # pyyaml, rich, paramiko, hvac, pytest
python3 -m pytest tests/          # 11 tests should pass on a fresh checkout
yamllint .                        # optional - .yamllint config is checked in
```

## Structure

- `roles/<role_name>/role.py` - one stage of the provisioning pipeline
  per role, each a plain Python module with a `run(target, apply,
  console, **kwargs)` function. Explicit registry in `roles/__init__.py`
  (`ROLES = {"name": module.run, ...}`) - not filesystem
  auto-discovery, so an unknown role name fails loudly instead of
  silently skipping.
- `modules/` - shared helper code used by 2+ roles in *this* project
  (inventory loading, SSH helpers, report writing). Sibling projects
  don't import each other's `modules/` or `roles/` - each project keeps
  its own copy of anything it needs, even if near-identical to another
  project's version. Deliberate convention: every project is
  independent and self-contained, so one project can be refactored,
  archived, or handed off without breaking any other.
- `modules/secrets.py` - OpenBao access (AppRole login + KV-v2 read via
  `hvac`), fully self-contained. OpenBao is the *primary* secrets
  mechanism: seed new credentials there first, and have roles read them
  with `get_secret("<project>/<name>")` instead of from local files.
  Configuration is env-var driven (`OPENBAO_ADDR`, `OPENBAO_CACERT`,
  `OPENBAO_SECRET_ID`, plus `openbao_role_id` in the gitignored
  `inventory/openbao_approle.yml`) - see the module docstring.
- `inventory/*.example.yml` - checked-in templates for the real
  `inventory/*.yml` files (gitignored, contain real IPs/hostnames/
  credentials-by-reference). Copy the `.example.yml`, fill it in, never
  commit the real one.
- `scripts/provision.py` - the CLI entry point: `--role <name> --host
  <vm_name>|--all [--apply]`. Dry-run by default.
- `tests/` - one `test_<role_name>.py` per role, plus
  `test_roles_registry.py` asserting every registered role's `run()`
  has the right signature.
- `reports/` - generated output (provisioning run reports, downloaded
  artifacts). Gitignored except `.gitkeep`; never commit real output.
