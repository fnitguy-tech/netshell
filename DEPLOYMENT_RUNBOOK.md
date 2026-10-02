# PROJECT_NAME - Deployment Runbook

**Status: template, not yet a real deployment.** Replace this whole doc
once there's a real build sequence to document.

## Prerequisites

- What must already exist/be reachable before starting (an identity
  server, a hypervisor cluster, a credential file, a sibling repo
  checked out alongside this one).

## Build sequence

1. `python3 scripts/provision.py --role example_install --host
   example-vm-01` (dry-run - review what it would do)
2. `python3 scripts/provision.py --role example_install --host
   example-vm-01 --apply`
3. Verify: (what to check after this step succeeds)

Repeat per stage in dependency order once there's more than one role.

## Fleet onboarding - if this project stood up a new VM/host

A new host isn't done when its service works: every fleet-wide system
you run needs to know it exists, and each one usually has its own
inventory. List them ALL here with the exact file/role to touch - this
checklist IS the doc, and a host missing from one of these is invisible
in exactly the situation you need it. Typical entries (replace with
your real systems and their inventory paths):

1. **Metrics + log shipping** - your collector's target inventory,
   then deploy the agent to the host.
2. **Security monitoring (SIEM agent)** - agent target inventory +
   install role.
3. **Compliance scanning** - scan-target inventory; non-default OS
   versions usually need their own benchmark/datastream entry.
4. **Patching** - patch-target inventory. Watch for silent drops: if
   the tooling only patches recognized OS versions, a typo here means
   the host is quietly never patched.
5. **Backups** - unless discovery is automatic, an explicit entry; if
   it IS automatic, write down *why* no entry is needed so nobody
   re-adds one "just in case".

Also record what deliberately needs **no** entry, with the reason -
the absence of an inventory line should be legible as a decision, not
an oversight. Delete this section if the project only targets existing
hosts.

## Real gotchas found during first live deployment

Nothing yet - this section exists so the *next* real gotcha has an
obvious place to go. Don't leave it empty once this project is actually built.
