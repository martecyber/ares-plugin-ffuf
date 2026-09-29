"""ffuf's customBuilder module — see AgentToolSpec.CustomBuilder's own doc (ares-core) for the
execution model this implements: ares-agent spawns this as an ISOLATED, short-lived subprocess
(never imported into its own process), with no access to the agent's auth token or config. It
reads one JSON object from stdin and writes one JSON object to stdout; it never touches the
network and never spawns ffuf itself — that's the agent's own job, with whatever command this
returns.

Why ffuf needs this at all (and no other tool does): a target may contain literal '*' wildcards
for multi-position fuzzing (e.g. "https://*.example.com/*/admin"), which ffuf expects rewritten
to FUZZ1/FUZZ2/... with one -w flag per position — a value transform driven by the target's own
internal structure, not expressible by AgentToolSpec's flat field->flag vocabulary. Every other
field (matchStatusCodes, threads, timeout, ...) is still declared normally in agent-tools.json
for core-side validation and UI rendering — but for THIS tool, ares-agent skips its own generic
flag-emission entirely and hands everything to this module instead (see build_command's args
shape below), so their emission logic (-mc, -fc, -t, ...) is duplicated here rather than shared.
That duplication is deliberately scoped to this one file, for this one tool.

Wire contract (stdin -> stdout, both single-line JSON):
  stdin:  {
    "binary": "/usr/bin/ffuf",           # resolved path, from shutil.which — this module never
                                          # searches PATH itself
    "outPath": "/path/to/workdir/ffuf.json",
    "target": "https://*.example.com/FUZZ",  # exactly one target (maxTargets=1 in the spec)
    "wordlist": "/path/to/cached/wordlist.txt",     # already resolved to a local path by the
                                                     # agent's generic server_fetch handling —
                                                     # this module never fetches from the KB itself
    "fuzzWordlists": ["/path/a.txt", "/path/b.txt"],  # same — pre-resolved local paths, one per
                                                       # '*' position in target, in order
    "urlTemplate": "https://{target}/FUZZ",  # used only when target has no '*'
    "matchStatusCodes": "200,301", "filterStatusCodes": null,
    "filterSize": null, "filterWords": null,
    "rate": null, "threads": null, "timeout": null,
    "extensions": null, "followRedirects": false, "autocalibrate": false,
    "recursion": false, "recursionDepth": null,
    "headers": ["X-Foo: bar"]
  }
  stdout: {"cmd": ["/usr/bin/ffuf", "-u", "...", "-w", "...:FUZZ1", "-of", "json", ...],
           "outPath": "/path/to/workdir/ffuf.json"}
          or {"error": "human-readable message"} on invalid input — the agent surfaces this as
          the task's failure reason without attempting to run anything.
"""
import json
import sys


def resolve_target(target: str, url_template: str, wordlist: str, fuzz_wordlists: list) -> tuple[str, list]:
    """Returns (url, wordlist_flags). No '*' in target: combine with url_template, use the
    single default wordlist. One or more '*': substitute each with FUZZ1, FUZZ2, ... and emit
    one -w flag per position, falling back to the default wordlist for any position beyond
    len(fuzz_wordlists)."""
    if "*" not in target:
        if "{target}" in url_template:
            full_url = url_template.replace("{target}", target.rstrip("/"))
        elif url_template.startswith("/"):
            full_url = target.rstrip("/") + url_template
        else:
            full_url = target.rstrip("/") + "/" + url_template
        return full_url, ["-w", wordlist]

    n = 0
    parts = []
    for ch in target:
        if ch == "*":
            n += 1
            parts.append(f"FUZZ{n}")
        else:
            parts.append(ch)
    substituted = "".join(parts)
    if "://" not in substituted:
        substituted = "https://" + substituted

    w_flags = []
    for idx in range(1, n + 1):
        wl = fuzz_wordlists[idx - 1] if idx - 1 < len(fuzz_wordlists) else wordlist
        w_flags += ["-w", f"{wl}:FUZZ{idx}"]
    return substituted, w_flags


def build_command(req: dict) -> dict:
    target = req.get("target")
    wordlist = req.get("wordlist")
    if not target or not wordlist:
        return {"error": "ffuf: 'target' and a resolved 'wordlist' are required"}

    url, w_flags = resolve_target(
        target, req.get("urlTemplate") or "https://{target}/FUZZ",
        wordlist, req.get("fuzzWordlists") or [])

    cmd = [req["binary"], "-u", url] + w_flags + ["-of", "json", "-o", req["outPath"], "-s"]

    if req.get("matchStatusCodes"):  cmd += ["-mc", str(req["matchStatusCodes"])]
    if req.get("filterStatusCodes"): cmd += ["-fc", str(req["filterStatusCodes"])]
    if req.get("filterSize") is not None:  cmd += ["-fs", str(int(req["filterSize"]))]
    if req.get("filterWords") is not None: cmd += ["-fw", str(int(req["filterWords"]))]
    if req.get("rate"):    cmd += ["-rate", str(int(req["rate"]))]
    if req.get("threads"): cmd += ["-t", str(int(req["threads"]))]
    if req.get("timeout"): cmd += ["-timeout", str(int(req["timeout"]))]
    if req.get("extensions"): cmd += ["-e", str(req["extensions"])]
    if req.get("followRedirects"): cmd.append("-r")
    if req.get("autocalibrate"):   cmd.append("-ac")
    if req.get("recursion"):
        cmd.append("-recursion")
        if req.get("recursionDepth"): cmd += ["-recursion-depth", str(int(req["recursionDepth"]))]
    for h in (req.get("headers") or []):
        cmd += ["-H", str(h)]

    return {"cmd": cmd, "outPath": req["outPath"]}


if __name__ == "__main__":
    request = json.loads(sys.stdin.readline())
    try:
        response = build_command(request)
    except Exception as e:
        response = {"error": f"ffuf builder: {e}"}
    sys.stdout.write(json.dumps(response))
