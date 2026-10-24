# Silent RCE Analysis: CVE-2026-109619 Crash Evasion Research

## Summary

We investigated whether an attacker could modify the CVE-2026-109619 exploit to achieve **silent RCE** — command execution where the Apache worker survives, evading crash-based detection systems like PHP Sentinel's canary array.

**Finding: Silent RCE requires root privileges on the container.** The crash is inherent to the unprivileged exploit path and cannot be suppressed without patching the worker's executable memory via `/proc/PID/mem`. Since the initial (crash-inducing) RCE must fire first to gain any foothold, PHP Sentinel detects the attack before the evasion technique could ever be deployed.

## Background

CVE-2026-109619 is a use-after-free in PHP's session upload progress handling under mod_php/Apache prefork. The exploit:

1. **Stage 1** — Heap leak: triggers OOM via large multipart upload, reads stale session cookie to recover a Zend MM chunk base address
2. **Stage 2** — Code leak: similar technique to leak `libphp.so` base from a `zval_ptr_dtor` pointer in the session data
3. **Stage 3** — Forged HashTable: places a crafted `HashTable` structure in reclaimed memory with `pDestructor` set to `zif_passthru`, causing PHP's hash table cleanup to execute an attacker-controlled command

## Why the Worker Crashes

During stage 3 cleanup, `zend_array_destroy` processes the forged HashTable:

1. Calls `pDestructor` (zif_passthru) on each bucket — **command executes here**
2. Frees the `arData` region via `_efree` — this succeeds (valid 192-byte bin boundary)
3. Frees the HashTable structure itself via `_efree_56` — **this crashes**

The crash occurs because `_efree_56` expects a pointer aligned to a 56-byte bin slot. The forged HashTable lives at offset +24 bytes inside a 192-byte `zend_string` allocation, which is not a valid 56-byte boundary. The Zend MM free-list corruption triggers `SIGABRT`.

The `_efree_56` call is a tail-call (`jmp _efree_56@plt`) at two exit points in `zend_array_destroy`:
- `libphp+0x613c02`: `e9 79 69 b4 ff` (primary path, `nIteratorsCount == 0`)
- `libphp+0x613c2b`: `e9 50 69 b4 ff` (secondary path via `iterators_remove`)

## The Silent Variant Approach

To suppress the crash, replace both `jmp _efree_56` instructions with `ret` + NOP padding (`c3 90 90 90 90`). At those points, callee-saved registers are already restored and the stack holds a valid return address. The `ret` returns cleanly to the caller, leaking only the 56-byte HashTable structure allocation.

This patch must be applied to the worker's `.text` segment at runtime, before stage 3 fires.

## Why It Requires Root

The only mechanism to patch a running process's `.text` segment is writing to `/proc/PID/mem`. On Linux:

- **www-data (the worker's own user)** cannot open `/proc/PPID/mem` for writing. Yama `ptrace_scope=1` (default in most containers) restricts `/proc/PID/mem` access to direct parent-child relationships. The www-data Apache worker has zero effective capabilities (`cap_net_bind_service` only on the parent). We verified this with a compiled C test: `fopen("/proc/PPID/mem", "r+b")` returns `EPERM` for every open mode.

- **Root** can write to any process's `/proc/PID/mem`, including `.text` segments mapped `r-xp`. The kernel's `FOLL_FORCE` flag in `mem_write` bypasses page protections. We confirmed this works: a root PHP script successfully read the original bytes at both patch targets, wrote `c3 90 90 90 90`, and verified the patch.

There is no other path to modify `.text` at runtime without `CAP_SYS_PTRACE` or root.

## Experimental Confirmation

**Environment:** Docker container running `php:8.4.26-apache`, single prefork worker (`MaxRequestWorkers 1`), `SYS_PTRACE` capability, `seccomp=unconfined`.

| Test | Result |
|------|--------|
| Unprivileged RCE (no patch) | Command executes, worker crashes (SIGABRT) |
| Root reads `/proc/PID/mem` at patch targets | Reads correct bytes (`e97969b4ff`, `e95069b4ff`) |
| Root writes `ret` patch via `/proc/PID/mem` | Patch applies, verified via read-back |
| Worker serves requests after patch | Worker responds normally |
| Chunk base consistency across workers | Deterministic — same `mmap` address after every fork |
| www-data writes to `/proc/PPID/mem` | `EPERM` — blocked by Yama ptrace_scope |

**Symbol offsets (pinned php:8.4.26-apache image):**
- `zif_passthru`: `libphp+0x465380`
- `zval_ptr_dtor`: `libphp+0x65eb60`
- `zend_array_destroy`: `libphp+0x613b40`
- `_efree_56@plt`: `libphp+0x15a580`
- Patch target 1: `libphp+0x613c02`
- Patch target 2: `libphp+0x613c2b`

## Implications for PHP Sentinel

The silent RCE variant is **not a practical threat** to crash-based detection:

1. **The attacker must trigger the crash first.** The unprivileged exploit (stages 1-3) crashes the worker. There is no unprivileged path to suppress the crash. PHP Sentinel's canary array detects this crash and blocks the request.

2. **Root is required for the bypass.** Writing to `/proc/PID/mem` requires root or `CAP_SYS_PTRACE`. An attacker can only obtain these privileges by first exploiting the system — which means triggering the crash, which means getting caught.

3. **The bypass is per-worker and per-boot.** ASLR randomizes `libphp.so` base on each container restart. The attacker must re-leak addresses and re-patch after every worker restart. This is not a persistent backdoor.

4. **Detection gap is zero.** The exploit's information leak stages (1 and 2) themselves send OOM-triggering requests that crash workers. The canary array would flag these requests before the attacker even reaches stage 3.

**Conclusion:** Crash-based behavioral detection is sufficient for CVE-2026-109619. The crash is a structural consequence of the exploit's heap manipulation and cannot be avoided without privileges that presuppose prior compromise.
