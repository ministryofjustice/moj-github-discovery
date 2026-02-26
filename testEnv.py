#!/usr/bin/env python3
"""
gh_diag.py — Diagnose why `gh` auth differs between terminal and Jupyter (Codespaces).

Usage:
  python gh_diag.py
  GH_TOKEN=... python gh_diag.py
  !python gh_diag.py   (in Jupyter)

It will:
- print PATH/HOME details
- locate gh binary and show version
- show whether GH_TOKEN/GITHUB_TOKEN are present (length + sha256 prefix only)
- run `gh auth status`
- run `gh api /user` and `gh api /orgs/<org>/repos?page=1` (configurable)
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from typing import Dict, Tuple, Optional

ORG = os.environ.get("GH_DIAG_ORG", "ministryofsound")  # override if needed


def sha256_prefix(s: str, n: int = 10) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:n]


def redacted_token_info(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        return "MISSING"
    v_stripped = v.strip()
    changed = " (whitespace stripped differs!)" if v != v_stripped else ""
    return f"present len={len(v)} stripped_len={len(v_stripped)} sha256={sha256_prefix(v_stripped)}{changed}"


def run(cmd, env: Optional[Dict[str, str]] = None, timeout: int = 30) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def print_kv(title: str, kv: Dict[str, str]):
    print(f"\n=== {title} ===")
    for k, v in kv.items():
        print(f"{k}: {v}")


def main() -> int:
    print("### gh_diag.py")
    print("Python:", sys.version.replace("\n", " "))
    print("CWD:", os.getcwd())

    # Basic env snapshot (safe)
    keys = ["HOME", "USER", "SHELL", "PATH", "XDG_CONFIG_HOME", "GH_HOST", "CODESPACES", "GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN"]
    env_view = {k: (os.environ.get(k) or "MISSING") for k in keys}
    print_kv("Environment snapshot", env_view)

    print("\n=== Token presence (redacted) ===")
    print("GH_TOKEN:", redacted_token_info("GH_TOKEN"))
    print("GITHUB_TOKEN:", redacted_token_info("GITHUB_TOKEN"))

    # Locate gh
    gh_path = shutil.which("gh")
    print("\n=== gh binary ===")
    print("which gh:", gh_path or "NOT FOUND")
    if not gh_path:
        print("ERROR: `gh` is not on PATH for this process.")
        return 2

    rc, out, err = run([gh_path, "--version"])
    print("gh --version rc:", rc)
    print(out.strip() or err.strip())

    # Show gh config directories (no secrets)
    # gh uses HOME / XDG_CONFIG_HOME to find config
    config_dir = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.environ.get("HOME", ""), ".config")
    print("\n=== Config locations (expected) ===")
    print("XDG_CONFIG_HOME:", os.environ.get("XDG_CONFIG_HOME") or "MISSING")
    print("Computed config dir:", config_dir)
    print("Expected gh config path:", os.path.join(config_dir, "gh"))

    # Build env variants to test
    base_env = os.environ.copy()
    base_env.setdefault("GH_PROMPT_DISABLED", "1")

    # Variant A: as-is (whatever env/kernel currently has)
    variants = [("A_env_as_is", base_env)]

    # Variant B: force remove tokens to see stored-auth behavior
    env_no_token = base_env.copy()
    env_no_token.pop("GH_TOKEN", None)
    env_no_token.pop("GITHUB_TOKEN", None)
    variants.append(("B_no_token", env_no_token))

    # Variant C: force GH_TOKEN from whichever is set; strip whitespace
    token = (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip()
    if token:
        env_force_token = base_env.copy()
        env_force_token["GH_TOKEN"] = token
        env_force_token.pop("GITHUB_TOKEN", None)  # avoid ambiguity
        variants.append(("C_force_GH_TOKEN_stripped", env_force_token))
    else:
        print("\nNOTE: No token present to test force-token mode (Variant C).")

    def do_calls(label: str, env: Dict[str, str]):
        print(f"\n\n######################## {label} ########################")

        # 1) auth status
        rc, out, err = run([gh_path, "auth", "status"], env=env)
        print("\n-- gh auth status --")
        print("rc:", rc)
        print((out or "").strip())
        print((err or "").strip())

        # 2) whoami via API (best proof)
        rc, out, err = run([gh_path, "api", "/user"], env=env)
        print("\n-- gh api /user --")
        print("rc:", rc)
        if out.strip():
            try:
                j = json.loads(out)
                print("login:", j.get("login"))
                print("id:", j.get("id"))
            except Exception:
                print(out[:1000])
        if err.strip():
            print("stderr:", err.strip()[:1000])

        # 3) org repos page 1
        rc, out, err = run([gh_path, "api", f"/orgs/{ORG}/repos?page=1"], env=env)
        print(f"\n-- gh api /orgs/{ORG}/repos?page=1 --")
        print("rc:", rc)
        if out.strip():
            # Print just count + a couple names
            try:
                arr = json.loads(out)
                names = [r.get("name") for r in arr[:5] if isinstance(r, dict)]
                print("repos_returned:", len(arr) if isinstance(arr, list) else "n/a")
                print("first_few:", names)
            except Exception:
                print(out[:1000])
        if err.strip():
            print("stderr:", err.strip()[:1000])

    for label, env in variants:
        do_calls(label, env)

    print("\n\n### Interpretation guide")
    print("- If Variant B_no_token works but Variant C_force_GH_TOKEN_stripped fails:")
    print("    => stored gh login is fine, but the token is not accepted (or wrong host/scopes).")
    print("- If Variant A_env_as_is differs between terminal and notebook:")
    print("    => kernel env differs (token missing, different HOME/PATH).")
    print("- If `which gh` differs between terminal and notebook:")
    print("    => different gh binary/version being used.")
    print("- If all variants fail in notebook but work in terminal:")
    print("    => most likely PATH/HOME/XDG_CONFIG_HOME differences or the kernel started before secrets were injected.")
    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
