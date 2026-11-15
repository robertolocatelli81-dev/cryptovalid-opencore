#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Every commit of a range carries a Signed-off-by trailer of its author (Developer Certificate of Origin 1.1).

    python3 check_dco.py <range>                 e.g. origin/master..HEAD ; exit 0 all signed, 1 some not, 2 usage
    python3 check_dco.py --count <range>         only count (exit 0): the measure of the existing history
    options: -C <repo>   --exempt-author <email> (repeatable; an automated account whose commits are not contributions
             of a person, named one by one in CONTRIBUTING.md)

Rule (OSPS Baseline LE-01.01: "code contributors must assert that they are legally authorized to make the associated
contributions on every commit"): a commit passes when one of its Signed-off-by trailers has the form `Name <email>`
and its email equals the author's or the committer's email (case-insensitive). Merge commits are not checked: they
carry no change of their own. Standard library and the `git` command only; no external service.
"""
import re
import subprocess
import sys

SOB = re.compile(r"^(?P<name>[^<>\n]*\S)\s+<(?P<email>[^<>\s]+@[^<>\s]+)>$")
SEP = "\x1e"


def commits(rev_range, repo="."):
    fmt = "%H%x00%ae%x00%ce%x00%s%x00%(trailers:key=Signed-off-by,valueonly,unfold)" + "%x1e"
    r = subprocess.run(["git", "-C", repo, "log", "--no-merges", "--format=" + fmt, rev_range],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise ValueError(r.stderr.strip() or "git log failed")
    out = []
    for rec in r.stdout.split(SEP):
        rec = rec.strip("\n")
        if not rec:
            continue
        h, ae, ce, subject, trailers = rec.split("\x00", 4)
        out.append({"hash": h, "author_email": ae, "committer_email": ce, "subject": subject,
                    "signoffs": [t.strip() for t in trailers.split("\n") if t.strip()]})
    return out


def problem(c, exempt=()):
    """None when the commit passes, otherwise the reason."""
    if c["author_email"].lower() in {e.lower() for e in exempt}:
        return None
    if not c["signoffs"]:
        return "no Signed-off-by trailer"
    emails = set()
    for s in c["signoffs"]:
        m = SOB.match(s)
        if m:
            emails.add(m.group("email").lower())
    if not emails:
        return "Signed-off-by is not of the form `Name <email>`"
    if not emails & {c["author_email"].lower(), c["committer_email"].lower()}:
        return "no Signed-off-by with the email of the author (%s)" % c["author_email"]
    return None


def main(argv):
    repo, exempt, count, rest = ".", [], False, []
    it = iter(argv)
    for a in it:
        if a == "-C":
            repo = next(it, None)
        elif a == "--exempt-author":
            exempt.append(next(it, None))
        elif a == "--count":
            count = True
        elif a.startswith("-"):
            rest = []
            break
        else:
            rest.append(a)
    if len(rest) != 1 or repo is None or None in exempt:
        sys.stderr.write(__doc__.split("\n\n")[1] + "\n")
        return 2
    try:
        cs = commits(rest[0], repo)
    except ValueError as e:
        sys.stderr.write("check_dco: %s\n" % e)
        return 2
    bad = [(c, p) for c in cs for p in [problem(c, exempt)] if p]
    if count:
        print("commits: %d  signed off: %d  not signed off: %d" % (len(cs), len(cs) - len(bad), len(bad)))
        return 0
    for c, p in bad:
        print("%s %s: %s" % (c["hash"][:12], c["subject"][:60], p))
    print("DCO: %d of %d commits pass" % (len(cs) - len(bad), len(cs)))
    if not cs:
        print("DCO: the range is empty: nothing was checked")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
