"""Write the plain-English comment for each setting into every `.env*` file.

WHY THIS EXISTS. The same 164 settings are documented in four files (.env, .env.uat,
.env.example, .env.prod.example) and the comments were maintained by hand in all four. They
drifted, predictably: 43% of .env.uat's settings had no comment at all, one comment described a
setting that had been deleted (the actor-vocabulary text left sitting above
TSG_MAX_PROPOSAL_CHARS, where 3500 reads as a cache timeout), and the wording that did exist was
written for someone who already knew the code.

So the description lives in ONE place — scripts/env_comments.py — and this applies it. Editing a
description updates four files; hand-editing four files is what caused the drift.

It rewrites ONLY the comment block directly above a setting's entry line. Section headers,
standalone prose and every VALUE are left exactly as they are: the value side is asserted
byte-identical afterwards, because .env.uat generates the OpenShift Secret and a stray character
there ships to the cluster.

Usage:  python scripts/apply_env_comments.py [--check]
        --check reports what would change and exits 1 if anything would, changing nothing.
"""
from __future__ import annotations

import re
import sys
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from env_comments import COMMENTS

ROOT = Path(__file__).resolve().parents[1]
WIDTH = 96

#: A setting's own entry line, live (`NAME=`) or commented out (`# NAME=`). Same shape
#: app/core/env_selfcheck.py matches, so "documented" means the same thing in both places.
ENTRY = re.compile(r"^([ \t]*#?[ \t]*)([A-Z][A-Z0-9_]*)([ \t]*=)")


def _wrap(text: str) -> list[str]:
    """Comment lines at WIDTH columns. A blank line starts a new paragraph, and a paragraph
    indented two further spaces is kept verbatim — that is how a command or an example keeps
    its own layout instead of being reflowed into prose.

    dedent first: the descriptions are triple-quoted inside a dict, so every line carries the
    source file's indentation. Without this, ALL of them would look pre-formatted.
    """
    out: list[str] = []
    for para in textwrap.dedent(text).strip("\n").split("\n\n"):
        if out:
            out.append("#")          # keep the author's paragraph break; unreadable without it
        if para.startswith("  "):
            out += [f"#{ln}" if ln.strip() else "#" for ln in para.split("\n")]
            continue
        line = "#"
        for word in para.split():
            if len(line) + 1 + len(word) > WIDTH:
                out.append(line)
                line = "#"
            line += " " + word
        out.append(line)
    return out


def _block_start(lines: list[str], i: int) -> int:
    """First line of the comment block immediately above lines[i].

    A blank line ends the block — that is what separates one setting's comment from the previous
    setting's. A section header (`# --- 9. Step 1 ...`) ends it and is never consumed, and
    neither is a neighbouring COMMENTED-OUT setting, which owns its own comment.
    """
    start = i
    while start > 0:
        prev = lines[start - 1]
        stripped = prev.strip()
        if not stripped.startswith("#") or stripped.startswith(("# ---", "# ===")):
            break
        if ENTRY.match(prev):
            break
        start -= 1
    return start


def rewrite(path: Path) -> tuple[str, int, list[str]]:
    """→ (new text, settings rewritten, TSG_ settings in this file with no description yet)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    i, done, missing = 0, 0, []
    while i < len(lines):
        m = ENTRY.match(lines[i])
        if not m or m.group(2) not in COMMENTS:
            if m and m.group(2).startswith("TSG_"):
                missing.append(m.group(2))
            out.append(lines[i])
            i += 1
            continue
        start = _block_start(lines, i)
        if i > start:
            # Everything since the previous entry line was appended one-for-one, so the last
            # (i - start) items of `out` are exactly the old comment block.
            del out[len(out) - (i - start):]
        # Every setting now carries a multi-line description, so without a gap the end of one
        # runs straight into the start of the next and the file becomes a wall of grey.
        if out and out[-1].strip() and not out[-1].startswith(("# ---", "# ===")):
            out.append("")
        out += _wrap(COMMENTS[m.group(2)])
        out.append(lines[i])
        done += 1
        i += 1
    return "\n".join(out) + "\n", done, missing


def main() -> int:
    check = "--check" in sys.argv
    changed = False
    for name in (".env", ".env.uat", ".env.example", ".env.prod.example"):
        path = ROOT / name
        if not path.exists():
            print(f"{name}: absent, skipped")
            continue
        new, done, missing = rewrite(path)
        differs = new != path.read_text(encoding="utf-8")
        changed |= differs
        if not check and differs:
            path.write_text(new, encoding="utf-8")
        print(f"{name}: {done} settings commented"
              f"{f', {len(set(missing))} still without a description' if missing else ''}"
              f"{' (would change)' if check and differs else ''}")
        if missing:
            print(f"    {', '.join(sorted(set(missing))[:10])}")
    return 1 if (check and changed) else 0


if __name__ == "__main__":
    raise SystemExit(main())
