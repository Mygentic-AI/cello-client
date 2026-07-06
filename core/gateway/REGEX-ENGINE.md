# The CELLO gateway regex engine (RE2)

The security gateway screens **content controlled by a remote peer** — inbound messages, the
injection-pattern matcher, the secret detectors. Any regular expression that runs on that content
must be **ReDoS-safe**: a normal backtracking regex engine (including JavaScript's built-in
`RegExp`) can be made to take exponential time on a small crafted input, which would peg the
gateway's CPU. That is both a denial-of-service and a way to *force a timeout verdict*, so it would
undermine the never-hang guarantee.

The gateway therefore runs these patterns on **RE2** (Google's engine), which guarantees time
**linear in the input length — no backtracking, ever.**

## Two engines, one behaviour

The gateway ships with **two** ways to get RE2, and picks the best one available at startup:

| Engine | npm package | Install | Notes |
|---|---|---|---|
| **Native** (preferred) | `re2` (an **optionalDependency**) | Downloads a prebuilt binary for your platform; compiles from C++ only if no prebuilt matches | Maintained, fastest. A failed build is **non-fatal** — the install continues without it. |
| **WASM** (fallback floor) | `re2-wasm` (a regular dependency) | A prebuilt `.wasm` file — **no compile, ever, on any platform** | Same RE2 algorithm, ~2-4× slower, always present. |

At startup the gateway does, in effect, `try { load native re2 } catch { load re2-wasm }`. **You
always get real RE2** — native if its addon built on your machine, WASM otherwise. You never get a
broken install, and you never get an unsafe (backtracking) engine.

## Which engine am I running?

The gateway prints it on its ready line:

```
GATEWAY_READY /path/to/socket regex-engine=native
```

`regex-engine=native` is the fast, maintained path. `regex-engine=wasm` means the native addon did
not build on this machine — everything still works (same guarantee), just a little slower.

## Forcing the native engine

If you see `regex-engine=wasm` and want the faster native engine, the native addon needs a C++
toolchain on the machine:

- **macOS:** `xcode-select --install`
- **Debian/Ubuntu:** `sudo apt-get install -y build-essential python3`
- **RHEL/Fedora:** `sudo dnf install -y gcc-c++ make python3`
- **Windows:** install the "Desktop development with C++" workload from the Visual Studio Build
  Tools.

Then rebuild the native addon and restart the gateway:

```
npm rebuild re2     # or: pnpm rebuild re2
```

## Why both, and not just one

- **Just native** would mean `npm install` can *fail* (or silently skip) on a machine without a C++
  toolchain, and native addons are the single most common cause of broken installs.
- **Just WASM** installs everywhere but is unmaintained and slower.

Carrying both costs a little more install (you always pull the WASM floor *and* attempt native), and
in exchange you get the best engine that will build, with a guaranteed safe floor and no install
that can break. For a security component screening untrusted input, that trade is the right one.
