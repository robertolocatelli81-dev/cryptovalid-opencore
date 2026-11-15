// cvtile-oracle — INDEPENDENT reader of C2SP tiles (added 2026-11-15), the oracle of SPEC §14 in tests and CI.
//
// It contains no cryptovalid code. Tile hashes are read and checked against the tree with golang.org/x/mod/sumdb/tlog
// (TileHashReader, TreeHash); tile paths are built by filippo.io/torchwood (c2sp.org/tlog-tiles) and filippo.io/sunlight
// (c2sp.org/static-ct-api); static CT data tiles are parsed by sunlight.ReadTileLeaf and entry bundles by
// torchwood.ReadTileEntry, and every entry is hashed with tlog.RecordHash against its level-0 hash.
//
//	usage: cvtile-oracle <dir> <size> <root-base64> <static-ct-api|tlog-tiles> [entries]
//	exit 0 = VERIFIED (the tiles give that root; with "entries", every entry hashes to its leaf and, for static CT,
//	carries its own index); exit 1 = not verified (the reason is printed); exit 2 = usage.
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"filippo.io/sunlight"
	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

type dirReader struct {
	dir     string
	profile string
}

func (r dirReader) path(t tlog.Tile) string {
	if r.profile == "static-ct-api" {
		return sunlight.TilePath(t)
	}
	return torchwood.TilePath(t)
}

// read returns the tile, or the prefix of the full tile when the partial one is absent (both specifications let a log
// delete a partial tile once the full one exists).
func (r dirReader) read(t tlog.Tile) ([]byte, error) {
	b, _, err := r.readFrom(t)
	return b, err
}

// readFrom also says whether the bytes are those of the full tile (a partial tile that is absent).
func (r dirReader) readFrom(t tlog.Tile) ([]byte, bool, error) {
	b, err := os.ReadFile(filepath.Join(r.dir, filepath.FromSlash(r.path(t))))
	if err == nil || t.W == torchwood.TileWidth || !os.IsNotExist(err) {
		return b, false, err
	}
	full := t
	full.W = torchwood.TileWidth
	b, err = os.ReadFile(filepath.Join(r.dir, filepath.FromSlash(r.path(full))))
	if err != nil {
		return nil, true, err
	}
	n := t.W * tlog.HashSize
	if t.L == -1 { // a data tile: the caller reads the first W entries
		return b, true, nil
	}
	if len(b) < n {
		return nil, true, fmt.Errorf("full tile shorter than the partial width")
	}
	return b[:n], true, nil
}

func (r dirReader) Height() int { return torchwood.TileHeight }
func (r dirReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, t := range tiles {
		b, err := r.read(t)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}
func (r dirReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {}

func fail(format string, a ...any) {
	fmt.Printf("FAIL: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 5 || len(os.Args) > 6 || (len(os.Args) == 6 && os.Args[5] != "entries") ||
		(os.Args[4] != "static-ct-api" && os.Args[4] != "tlog-tiles") {
		fmt.Println("usage: cvtile-oracle <dir> <size> <root-base64> <static-ct-api|tlog-tiles> [entries]")
		os.Exit(2)
	}
	size, err := strconv.ParseInt(os.Args[2], 10, 64)
	if err != nil || size < 0 {
		fmt.Println("usage: size")
		os.Exit(2)
	}
	rootB, err := base64.StdEncoding.DecodeString(os.Args[3])
	if err != nil || len(rootB) != tlog.HashSize {
		fmt.Println("usage: root")
		os.Exit(2)
	}
	var root tlog.Hash
	copy(root[:], rootB)
	r := dirReader{dir: os.Args[1], profile: os.Args[4]}
	hr := tlog.TileHashReader(tlog.Tree{N: size, Hash: root}, r)
	got, err := tlog.TreeHash(size, hr)
	if err != nil {
		fail("%v", err)
	}
	if got != root {
		fail("root differs")
	}
	if len(os.Args) == 6 && size > 0 {
		idx := make([]int64, size)
		for i := range idx {
			idx[i] = tlog.StoredHashIndex(0, int64(i))
		}
		leaves, err := hr.ReadHashes(idx)
		if err != nil {
			fail("%v", err)
		}
		for n := int64(0); n*torchwood.TileWidth < size; n++ {
			w := size - n*torchwood.TileWidth
			if w > torchwood.TileWidth {
				w = torchwood.TileWidth
			}
			t := tlog.Tile{H: torchwood.TileHeight, L: -1, N: n, W: int(w)}
			b, fromFull, err := r.readFrom(t)
			if err != nil {
				fail("%v", err)
			}
			if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
				z, err := gzip.NewReader(bytes.NewReader(b))
				if err != nil {
					fail("gzip: %v", err)
				}
				if b, err = io.ReadAll(z); err != nil {
					fail("gzip: %v", err)
				}
			}
			for i := int64(0); i < w; i++ {
				var leaf []byte
				pos := n*torchwood.TileWidth + i
				if r.profile == "static-ct-api" {
					e, rest, err := sunlight.ReadTileLeaf(b)
					if err != nil {
						fail("entry %d: %v", pos, err)
					}
					if e.LeafIndex != pos {
						fail("entry %d: leaf index %d", pos, e.LeafIndex)
					}
					leaf, b = e.MerkleTreeLeaf(), rest
				} else {
					e, rest, err := torchwood.ReadTileEntry(b)
					if err != nil {
						fail("entry %d: %v", pos, err)
					}
					leaf, b = e, rest
				}
				if tlog.RecordHash(leaf) != leaves[pos] {
					fail("entry %d does not hash to its leaf", pos)
				}
			}
			if !fromFull && len(b) != 0 {
				fail("bytes after the entries of tile %d", n)
			}
		}
	}
	fmt.Printf("VERIFIED size=%d root=%s\n", size, base64.StdEncoding.EncodeToString(root[:]))
}
