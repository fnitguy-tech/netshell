# PROJECT_NAME - Infrastructure Prerequisites

**Status: template.** Only needed if the prerequisites are involved
enough that they don't fit cleanly in the README - many smaller
projects condense this into the README instead and delete this file.
Say so explicitly in the README if you do that.

## External infrastructure this depends on

What must already exist and be reachable (an identity server, a DNS
zone, a specific network VLAN, a secrets store).

## Credentials/access needed

What credentials this project's automation needs, and where they come
from - never a real secret value in this doc. Convention: OpenBao
is the *primary* secrets mechanism, not one option among several. When
the project needs a new credential (service password, API token, bind
account), seed it into OpenBao first (`bao kv put ...`) and record the
OpenBao path here.
Role code reads it via `modules.secrets.get_secret()` - see that
module's docstring for the required environment (`OPENBAO_ADDR`,
`OPENBAO_CACERT`, `OPENBAO_SECRET_ID`, and the AppRole role_id in
`inventory/openbao_approle.yml`). A gitignored local inventory file is
the offline fallback, not the primary store.
