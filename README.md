# 🛡️ Single-File AV Scanner + Sandbox — in C

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![C99](https://img.shields.io/badge/language-C99-blue.svg)](scanner.c)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)](scanner.c)
[![Offline](https://img.shields.io/badge/network-100%25%20offline-red.svg)](scanner.c)
[![Version](https://img.shields.io/badge/version-0.2.0-orange.svg)](scanner.c)

**A fully offline, single-file antivirus scanner + sandbox in C. No network. No VirusTotal. No dependencies.**

One `.c` file. Two commands. Twenty-five defensive detection modules. Built for learning, labs, and open-source triage — not to replace your commercial AV, but to show exactly how static detection works under the hood.

> Real talk: no offline scanner catches 100% of malware. This one doesn't pretend to. What it does is give you **transparent, auditable, dependency-free** detection — every rule readable in one file.

Works on **Windows (MinGW / MSVC)** and **Linux (gcc)**. Compiles in seconds. Runs anywhere.

---

## ⚡ Quickstart

```sh
# 1. Build (pick your platform)
gcc scanner.c -o scanner -Wall -Wextra -O2 -lm        # Linux
gcc scanner.c -o scanner.exe -Wall -Wextra -O2        # Windows (MinGW)
cl scanner.c                                          # Windows (MSVC)

# 2. Self-test (no disk writes, verifies SHA-256 + EICAR + entropy)
./scanner sigtest
# sigtest: PASS (eicar-mem=1 clean=0 sha256-abc=ok entropy=ok)

# 3. Scan a folder
./scanner scan ./test-folder

# 4. Sandbox a suspicious binary (contained, 15s timeout)
./scanner sandbox ./suspicious.exe
```

Prefer the manual? [Read the full CLI reference ↓](#-cli-reference)

---

## ✨ Why this scanner?

| | This project | Typical AV |
|---|---|---|
| **Source size** | 1 file (~1,500 lines) | Millions of lines, closed source |
| **Dependencies** | Zero (stdlib + OS API only) | Dozens |
| **Network calls** | None. Ever. | Cloud lookups, telemetry |
| **Auditable** | Read it in one sitting | Black box |
| **Sandbox included** | Yes (Job Object / rlimit) | Separate product |
| **Price** | Free, MIT | Subscription |

---

## 🧩 Detection engine — 25 modules, 1 file

### Signatures & identity

| Module | What it does |
|---|---|
| EICAR signature | Industry-standard test string → `HIT` |
| Hex-signature table | Compiled-in custom patterns, chunked matching |
| SHA-256 | Dependency-free implementation, canonical file ID |
| FNV-1a | Fast pre-filter before SHA-256 confirm |

### Structural analysis

| Module | What it does |
|---|---|
| PE anomaly detector | MZ/PE magic, section bounds, entry-point-in-executable check |
| ELF anomaly detector | Header bounds, RWX segment, W+X section flags |
| Entropy triage | Shannon entropy ≥ 7.2 + ≥ 512 B → `PACKED` note (never a verdict alone) |
| Container checks | OLE (`D0CF11E0`) vs OOXML (`PK..`) magic, extension mismatch |

### Heuristics (report-only, never execute)

| Module | What it does |
|---|---|
| Persistence strings | `Run` keys, `schtasks`, services, WMI event consumers |
| Credential strings | `mimikatz`, `sekurlsa`, `ntds.dit`, `lsass` |
| Downloader cradles | `-EncodedCommand`, `FromBase64String`, `DownloadString` |
| LOLBin names | `powershell`, `mshta`, `rundll32`, `certutil`, `bitsadmin`, `msbuild`… |
| Ransomware strings | Ransom-note filenames, `vssadmin`, `shadowcopy`, log-wipe commands |
| Script obfuscation | 500+ char base64 blobs, 2000+ char lines, char-code arrays (`.ps1/.bat/.js/.vbs`) |
| LNK analysis | Suspicious targets + args (`powershell`, `http`, hidden flags) |
| Office macros | Auto-exec keywords (`AutoOpen`, `Document_Open`) + `vbaProject` presence |
| Double extension | `invoice.pdf.exe`, `doc.lnk` masquerades |
| Network IOCs | Embedded `http(s)://`, `.onion`, IPv4-like literals (no traffic, strings only) |
| Anti-analysis strings | VM/sandbox tool names **in the scanned file** (detection, not evasion) |

### Containment & platform

| Module | What it does |
|---|---|
| Windows sandbox | Job Object: 3 processes, 512 MB, UI restrictions, kill-on-close, 15 s timeout |
| Linux sandbox | `fork` + `rlimit` (CPU/AS/NPROC/FSIZE) + process-group `killpg`, 15 s timeout |
| Safe traversal | Depth cap 32, never follows symlinks, skips `/proc /sys /dev` |
| Lab context log | CPUID hypervisor bit → log line only, zero behavior change |

---

## 📋 Verdict policy (fail-closed, FP-safe)

```
HIT         → strong signature only (EICAR). Counts as detection.
SUSPICIOUS  → structural anomaly / strong heuristic. Needs analyst review.
INFO        → single weak signal, packed note, embedded IP. Context only.
CLEAN       → silent. No output.
```

Rules that keep false positives down:

- Extension, size, or hash **alone** can never produce `HIT`
- Entropy **alone** can never produce `SUSPICIOUS`
- `desktop.ini`, `thumbs.db`, `.DS_Store` are allowlisted to `CLEAN`
- Anything over 64 MB is skipped with `SKIP-LARGE` (never silently passed)

---

## 🖥️ Build matrix

| Platform | Compiler | Command | Output |
|---|---|---|---|
| Linux | `gcc` | `gcc scanner.c -o scanner -Wall -Wextra -O2 -lm` | `scanner` |
| Windows (MinGW) | `gcc` | `gcc scanner.c -o scanner.exe -Wall -Wextra -O2` | `scanner.exe` |
| Windows (MSVC) | `cl` | `cl scanner.c` | `scanner.exe` |

Requirements: a C99 compiler. That's it. No package manager, no libraries, no internet.

---

## 📖 CLI reference

```sh
scanner scan <folder> [--json]   # recursive offline scan
scanner sandbox <exe> [args...]  # contained execution, 15s timeout
scanner hash <file>              # print FNV-1a + SHA-256 + size
scanner sigtest                  # in-memory self-test (EICAR + SHA-256 + entropy)
scanner --version | --help
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Clean (no HIT / SUSPICIOUS) |
| `1` | Detection found |
| `2` | Usage error |
| `3` | Runtime / I/O error |
| `4` | Sandbox timeout (process tree killed) |
| `5` | Sandbox child exited non-zero |

### Example — text output

```
[HIT] EICAR-TEST | ./test/eicar.com | size=68 fnv=a4e9529dd846285b sha256=275a021bbfb6489e... ent=4.12
[SUSPICIOUS] PE-ANOMALY:13 +PACKED | ./test/packed.exe | size=512000 fnv=9f2c... ent=7.81
[INFO] PACKED-NOTE ent=7.65 | ./test/driver.zip | size=204800

---
Scanned: 3 files, Hit: 1, Suspicious: 1, Info: 1, Errors: 0, Bytes: 717k (0.04s)
```

### Example — JSON output (`scan <folder> --json`)

```json
{"path":"./test/eicar.com","size":68,"fnv1a":"a4e9529dd846285b","sha256":"275a021b…","entropy":4.12,"verdict":"HIT","reason":"EICAR-TEST"}
{"summary":{"files":3,"hit":1,"suspicious":1,"info":1,"errors":0,"bytes":717868,"secs":0.04},"result":"HIT"}
```

---

## 🧪 Testing

```sh
./scanner sigtest          # built-in vectors, no malware needed
```

| Test | Fixture | Expected |
|---|---|---|
| EICAR detection | File containing `EICAR-STANDARD-ANTIVIRUS-TEST-FILE` | `HIT` |
| Clean file | Plain `.txt` | `CLEAN` (silent) |
| Tiny risky file | 20-byte `.bat` | `INFO` / `SUSPICIOUS` |
| Double extension | `invoice.pdf.exe` | `SUSPICIOUS` |
| Large file | > 64 MB | `SKIP-LARGE` |
| Sandbox timeout | 30 s sleeper | `exit 4`, tree killed |

Your real-time AV may quarantine files containing the live EICAR string — the self-test uses an in-memory buffer precisely so you never need to write one to disk.

---

## ⚠️ Honest limitations

- **No zero-day guarantee.** Offline heuristics catch families and patterns, not novel payloads with no static footprint.
- **No behavior tracing.** The sandbox contains and times out; it doesn't log API calls or syscalls (see roadmap).
- **No cloud reputation.** By design — but that also means no prevalence data.
- **No AntiVM/AV bypass techniques — deliberately.** Detection of anti-analysis strings is included; evasion is not, and never will be in this repo.

---

## 🗺️ Roadmap

- [ ] Import-table sparsity check (PE)
- [ ] Syscall/API-call log in sandbox (ETW / strace-lite)
- [ ] `--quarantine` mode (move hits to isolated dir)
- [ ] Signed-vs-unsigned INFO signal (never a verdict)
- [ ] YARA-lite external rule file (`--rules rules.txt`)

Contributions welcome — keep it **one file, zero deps, offline**. See [Contributing](CONTRIBUTING.md) if added, or just open a PR.

---

## 📄 License

MIT — see [LICENSE](LICENSE). Use it, fork it, teach with it.

Built by [@dupewon](https://github.com/dupewon) — single-file defensive tooling.
