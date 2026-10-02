# Using this template

Steps to turn this into a real project after creating a repo from it.

**First, verify the fresh checkout works** before renaming anything -
it's much easier to debug a broken environment against the untouched
example code:

```bash
pip install -r requirements.txt        # pyyaml, rich, paramiko, hvac, pytest
python3 -m pytest tests/               # 11 tests should pass
cp inventory/vms.example.yml inventory/vms.yml
python3 scripts/provision.py --role example_install --host example-vm-01
```

The last command should print a `DRY RUN` line and write a report under
`reports/` (`provision_example_install_report.md`). Delete the copied
`inventory/vms.yml` afterward if you like - it's gitignored either way.

1. **Pick a name and rename things.** Replace every `PROJECT_NAME` and
   `example`/`example_install` placeholder (repo name, `README.md`'s
   title, `roles/example_install/` directory name and its contents,
   test file names) with your real project name - and don't forget the
   example inventory values (`example-vm-01`, `hv-example-01`,
   `~/.ssh/id_ed25519_example`). `grep -rn
   "PROJECT_NAME\|example_install\|example-vm-01\|hv-example-01\|id_ed25519_example" .`
   to find every spot.

2. **Decide whether this really deserves a standalone repo** or should
   be a subdirectory inside an existing automation monorepo you already
   run. This template is for the standalone-repo case; if you keep a
   monorepo, a new subdirectory there is often the better default and a
   whole new repo the exception.

3. **Write your first real role** in the role directory you renamed in
   step 1 (`roles/<your_role_name>/role.py`, formerly
   `roles/example_install/`), following the pattern already stubbed
   there:
   - `run(target, apply, console, **kwargs)` signature, always.
   - Dry-run first: if `not apply`, print what *would* happen and
     `return {"host": ..., "status": "dry_run"}` without touching
     anything.
   - Wrap real work in `try`/`except`, returning `{"host": ..., "status":
     "failed", "error": str(e)}` on failure - never let one host's
     exception abort a batch run across many hosts.
   - Check `run_ssh_command()`'s `returncode`, not `success` - success
     only means the command *ran* (transport level); a command that ran
     and exited nonzero is still `success: True`. The example role and
     its tests show the pattern.
   - Anything large the role generates (a ruleset, a rendered config, a
     cert bundle) goes to the host via `modules.ssh_key.put_files()`,
     not inlined in the command string - one command is one argv entry,
     hard kernel cap of 128KB (see that function's docstring).
   - Register it in `roles/__init__.py`'s `ROLES` dict.

4. **Fill in `inventory/*.example.yml`** with the real shape your
   role(s) expect (VM definitions, hypervisor details, SSH key paths -
   whatever `modules/inventory.py`'s loaders will parse). This repo's
   `.gitignore` already ignores `inventory/*.yml` and negates
   `!inventory/*.example.yml` (no `projects/` prefix - that's the
   monorepo layout, not this one); if you rename the example files,
   make sure they still match that negation pattern.

5. **Wire up OpenBao for every credential** the project needs (service
   passwords, API tokens, bind accounts) - that's the primary secrets
   mechanism, not an optional add-on. Seed the secret into OpenBao
   first (`bao kv put <mount>/<project>/<name> ...`), create an AppRole
   for this project, put its role_id in
   `inventory/openbao_approle.yml` (copy the `.example.yml`), and read
   the secret in role code via `modules.secrets.get_secret()`. A
   gitignored local inventory file holds a *reference* to the secret,
   or serves as the offline fallback - never the primary store. Catch
   `SecretNotFoundError` only for genuinely optional integrations;
   never catch the base `SecretsClientError` to mean "use a default"
   (the module docstrings explain why).

6. **Write the matching test** in `tests/test_<role_name>.py` - mock
   SSH/network calls, assert on the dry-run message and the real
   command sequence, following `tests/test_example_install.py`'s
   pattern.

7. **Replace the skeleton sections** in `DEPLOYMENT_RUNBOOK.md`,
   `OPERATIONS_RUNBOOK.md`, and `docs/ARCHITECTURE.md` with real content
   once there's something real to document - don't leave placeholder
   text in a repo other people will read.

8. **Delete this file** once the project is real - it's meta-documentation
   about the template, not about your project.

## What NOT to copy blindly

- The pipeline shape shown in `roles/__init__.py`'s docstring is
  illustrative, not mandatory. Some projects have 2 stages, some have
  8 - use however many your actual provisioning goal needs. If the
  project targets existing infrastructure rather than provisioning new
  hosts, don't stub out provisioning stages just to match the pattern.
