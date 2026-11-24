# Privilege Escalation CTF — Technical Report

## Misconfig 1: Sudoers NOPASSWD

**Setup:** `ctfuser` was granted passwordless sudo on `/usr/bin/find` via `/etc/sudoers`.

**Exploit:**
```
sudo find . -exec /bin/sh -p ; -quit
```
`find` has a built-in `-exec` flag to run arbitrary commands on results. Since `find` runs as root (via sudo), the shell it spawns inherits root privileges. `-p` preserves those privileges.

**Why it's dangerous:** many common binaries (`find`, `vim`, `less`, `python3`, `awk`) have similar shell-escape capabilities — documented at GTFOBins.github.io. Granting sudo on them without restriction is a common real-world misconfiguration.

**Fix:** never grant NOPASSWD sudo on binaries with known shell-escape functionality. Restrict to specific arguments where possible, or avoid sudo entirely for such tools.

---

## Misconfig 2: Writable Cron Job

**Setup:** A root cron job runs `/opt/scripts/cleanup.sh` every minute. The script was mistakenly left world-writable (`chmod 777`).

**Exploit:**
```
echo '#!/bin/bash' > /opt/scripts/cleanup.sh
echo 'cp /bin/bash /opt/rootbash; chmod +s /opt/rootbash' >> /opt/scripts/cleanup.sh
```
Wait for the next cron cycle, then:
```
/opt/rootbash -p
```
Since cron executes the script as root, root makes the SUID copy on our behalf.

**Obstacle encountered:** initially placed the binary in `/tmp`, which failed silently — `/tmp` is mounted `nosuid`, so the kernel ignores SUID bits there. Moving the target to `/opt` (no such restriction) fixed it.

**Fix:** scheduled scripts should never be writable by non-owning users. Regular audits of cron script permissions (`find / -writable -path "*/cron*"`) catch this.

---

## Misconfig 3: Writable `/etc/passwd`

**Setup:** `/etc/passwd` permissions were set to `666` (world-writable) instead of the correct `644` (root-writable only).

**Exploit:**
```
openssl passwd -1 -salt xyz password123
echo 'hacker:<hash>:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker
```
Linux identifies root by UID 0, not by username — any entry with UID/GID `0:0` has full root privileges, regardless of name.

**Fix:** `/etc/passwd` must remain root-writable only. This is a baseline Linux file-permission check in any security audit.

---

## Misconfig 4: Custom C/C++ SUID Binary

**Setup:** A custom program (`vuln`), installed SUID-root, intended as a simple log viewer.

**Attempt 1 (failed):** built the file path via `system()`:
```c
snprintf(command, sizeof(command), "cat /var/log/app/%s", argv[1]);
system(command);
```
Command injection via `argv[1]` (e.g. `"x; /bin/sh -p"`) should have spawned a root shell, but `/bin/sh` on Ubuntu is `dash`, which detects real UID ≠ effective UID and drops privileges immediately — a deliberate hardening feature. Confirmed via `id`, which showed `uid=1001(ctfuser)` even inside the "exploited" shell.

**Attempt 2 (worked):** rewrote the program to avoid any shell call, using raw file operations instead:
```c
int src = open("/bin/bash", O_RDONLY);
int dst = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC, 0755);
// copy bytes...
chmod(argv[1], 04755);
```
No shell is invoked, so the process's effective root privilege is never dropped. The program trusts `argv[1]` completely, letting it write a SUID-root `bash` copy anywhere the caller specifies:
```
/usr/local/bin/vuln /opt/rootshell
/opt/rootshell -p
```

**Fix:** never build shell commands from unsanitized input (`system()`/`popen()`); use `execve()` with an explicit argument array. Also validate and restrict any file path a privileged program accepts from user input.

---

## C++ Harness

The harness (`harness/harness.cpp`) orchestrates and scores the above exploits:
- `fork()`/`exec()`/`waitpid()` — runs enumeration commands as child processes
- A background **thread** — asynchronous logging to `activity.log`
- A **mutex** — protects shared score/log-queue state from race conditions
- A **semaphore** — limits concurrent enumeration commands to 2
- **SHA-256 flag verification** — `flags.hash` stores only hashes, never plaintext, so submissions are checked without exposing answers (mirrors how real CTF platforms work)

---

## Summary

All four misconfigurations were independently exploited to obtain root, confirmed via `whoami`/`id`. Two (Misconfigs 2 and 4) required a second implementation attempt after hitting real Linux hardening mechanisms (`nosuid` mounts, `dash`'s privilege-dropping) — both diagnosed and resolved through legitimate alternative techniques rather than bypassed.
