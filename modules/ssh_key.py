"""Key-based SSH command execution. Every host this project manages is
assumed to be SSH-key-only (no password auth) - adjust if that's wrong
for your target infrastructure.

Self-contained on purpose: projects built from this template keep
their own copy of shared helpers rather than importing across repos,
so each project stays independently refactorable.
"""
import hashlib
import os

import paramiko


# FIPS fix (confirmed live in the lab 2026-08-02): paramiko computes an
# MD5 fingerprint of every key purely to build a DEBUG log line - even
# with DEBUG logging off. On a FIPS-mode host plain hashlib.md5() is
# blocked at the OS crypto-policy level, so every SSH connection from a
# FIPS host crashes before authentication starts
# (_hashlib.UnsupportedDigestmodError, surfacing as a generic "SSH
# failure"). usedforsecurity=False is the sanctioned fix, not a
# workaround: the fingerprint is only ever used for logging, never for a
# trust decision, and FIPS-validated OpenSSL honors the flag for
# non-security uses.
def _fips_safe_get_fingerprint(self):
    return hashlib.md5(self.asbytes(), usedforsecurity=False).digest()


paramiko.PKey.get_fingerprint = _fips_safe_get_fingerprint


class SSHKeyError(Exception):
    pass


def run_ssh_command(host, command, key_path, username="admin", connect_timeout=15,
                     exec_timeout=120, get_pty=False):
    """Runs a single command over SSH using key auth. Returns
    {"success": bool, "stdout": str, "stderr": str, "returncode": int}.
    Raises SSHKeyError on connection failure. `success` means the
    command RAN (transport-level success) - a command that ran but
    returned nonzero is still success=True; check `returncode` for the
    real result. Callers must check returncode, not success.

    connect_timeout and exec_timeout are deliberately separate - a dead
    host should fail fast, but a long remote command (package installs,
    enrollment scripts) legitimately runs past two minutes. Note
    exec_timeout governs each individual channel read, not total
    runtime: a command with periodic output can run indefinitely; it
    only fires on a single silent gap longer than the timeout.

    THE COROLLARY, AND IT HAS BITTEN (observed live 2026-08-19): a
    command that is COMPLETELY SILENT for a long time can hang this call
    forever - recv_exit_status() has no timeout and no transport
    keepalive is set, so if the idle TCP flow is dropped in between, the
    caller blocks even after the remote command finished cleanly. A role
    that runs something long-and-quiet must keep the channel talking:
    start the work async (e.g. `systemctl start --no-block`) and poll
    with short commands that print a heartbeat, rather than issuing one
    blocking command."""
    key_path = os.path.expanduser(key_path)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            host, username=username, key_filename=key_path,
            timeout=connect_timeout, banner_timeout=connect_timeout, auth_timeout=connect_timeout,
            look_for_keys=False, allow_agent=False,
        )
    except Exception as e:
        raise SSHKeyError(f"connect to {host} failed: {e}") from e

    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=exec_timeout, get_pty=get_pty)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        rc = stdout.channel.recv_exit_status()
    finally:
        client.close()

    return {"success": True, "stdout": out, "stderr": err, "returncode": rc}


def put_files(host, files, key_path, username="admin", connect_timeout=15,
              exec_timeout=120, mode=0o600):
    """Upload in-memory content to remote paths over SFTP.

    `files` is {remote_path: text}. Returns {remote_path: sha256-hex} so
    the caller can have the remote script verify what actually landed.

    WHY THIS EXISTS. run_ssh_command ships its whole script as ONE
    command string, so the script must fit in a single argv entry -
    MAX_ARG_STRLEN, a hard kernel limit of 131072 bytes - and the only
    diagnostic past it is `/bin/bash: Argument list too long`, which
    says nothing about size. Roles that embed a large generated artifact
    (a ruleset, a kickstart, a cert bundle) in a heredoc hit this. Stage
    the artifact here and have the script read it from disk instead.

    The caller is responsible for removing the staged file. Default mode
    is 0600 because these artifacts routinely contain credentials.
    """
    key_path = os.path.expanduser(key_path)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, username=username, key_filename=key_path,
            timeout=connect_timeout, banner_timeout=connect_timeout,
            auth_timeout=connect_timeout, look_for_keys=False, allow_agent=False,
        )
    except Exception as e:
        raise SSHKeyError(f"connect to {host} failed: {e}") from e

    digests = {}
    try:
        sftp = client.open_sftp()
        try:
            for remote_path, text in files.items():
                data = text.encode()
                with sftp.file(remote_path, "wb") as fh:
                    fh.write(data)
                sftp.chmod(remote_path, mode)
                # Verify the bytes that actually landed, not the bytes we
                # meant to send - a short write here would otherwise
                # surface much later as an unexplained parse failure.
                landed = sftp.stat(remote_path).st_size
                if landed != len(data):
                    raise SSHKeyError(
                        f"upload of {remote_path} to {host} is short: "
                        f"{landed} bytes on disk, {len(data)} sent"
                    )
                digests[remote_path] = hashlib.sha256(data).hexdigest()
        finally:
            sftp.close()
    finally:
        client.close()
    return digests
