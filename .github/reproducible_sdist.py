#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rewrite an sdist (.tar.gz) so that the same sources give the same bytes (15/11/2026).

setuptools writes the sdist with the build time in every tar member and in the gzip header, the builder's user and
group names, and the umask's modes: two builds of one commit differed (measured on 0.24.0 with setuptools 84.2.1, the
same SOURCE_DATE_EPOCH, contents identical). This keeps every member and its content, and fixes the rest:
members sorted by name, mtime = SOURCE_DATE_EPOCH (required), uid/gid 0, no user or group name, mode 0o755 for
directories and executable files and 0o644 for the others, PAX format (the sdist specification), gzip header without
file name and with mtime = SOURCE_DATE_EPOCH, compression level 9. Anything that is not a regular file or a directory
(a link, a device) is refused: an sdist has none.

usage: SOURCE_DATE_EPOCH=<seconds> python3 .github/reproducible_sdist.py dist/<name>.tar.gz [...]"""
import gzip
import io
import os
import sys
import tarfile


def rewrite(path: str, epoch: int) -> None:
    with tarfile.open(path, "r:gz") as src:
        members = []
        for m in src.getmembers():
            if not (m.isfile() or m.isdir()):
                raise SystemExit(f"{path}: member {m.name!r} is neither a file nor a directory")
            data = src.extractfile(m).read() if m.isfile() else None
            members.append((m, data))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as dst:
        for m, data in sorted(members, key=lambda x: x[0].name):
            t = tarfile.TarInfo(m.name)
            t.type, t.mtime, t.uid, t.gid, t.uname, t.gname = m.type, epoch, 0, 0, "", ""
            t.mode = 0o755 if m.isdir() or (m.mode & 0o111) else 0o644
            t.pax_headers = {}
            if data is not None:
                t.size = len(data)
                dst.addfile(t, io.BytesIO(data))
            else:
                dst.addfile(t)
    tmp = path + ".tmp"
    with open(tmp, "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=epoch) as gz:
            gz.write(buf.getvalue())
    os.replace(tmp, path)


def main(argv) -> int:
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
    if not epoch.isdigit():
        print("SOURCE_DATE_EPOCH must be set to a number of seconds (the date of the commit)", file=sys.stderr)
        return 2
    if not argv:
        print(__doc__.rsplit("usage: ", 1)[1], file=sys.stderr)
        return 2
    for p in argv:
        rewrite(p, int(epoch))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
