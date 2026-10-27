package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// MaxHeight bounds the height of the trees we accept. A proof longer than
// that is rejected without even being checked: a verifier should never let
// a prover make it do an unbounded amount of work.
const MaxHeight = 20

// Proof claims that Leaf sits at position Pos of the committed tree, and
// carries the sibling hashes needed to check it, bottom first. It is what
// travels between a prover and a verifier -- roughly a kilobyte for a tree
// of a million leaves.
type Proof struct {
	Leaf   []byte
	Pos    int
	Hashes [][]byte
}

// RootFromProof recomputes the root of the tree from the proof alone.
//
// You climb back up the path the prover walked down. At each level you hold
// the digest of the subtree you came from, and the proof gives you its
// sibling. The only thing you have to get right is the *order* of the two
// children, because HashInternal(a, b) and HashInternal(b, a) are two
// different digests -- and the order is what the position tells you: an
// even position is a left child, an odd position is a right child.
//
// [Task] Start from the hash of the leaf, then for each hash of the proof,
// combine it with what you hold, in the right order, and move up: the
// position of the parent is pos>>1.
func RootFromProof(p *Proof) []byte {
	return nil // TODO: fold the proof back into a root (section 7)
}

// Verify checks a proof against a published root. This is the operation a
// light client, or a smart contract, actually runs: it holds 32 bytes of
// committed state and a proof, and nothing else -- no tree, no list.
func Verify(p *Proof, root []byte) bool {
	if len(p.Hashes) > MaxHeight {
		return false // an unreasonably long proof, refuse to work
	}
	return bytes.Equal(RootFromProof(p), root)
}

// WriteProof writes a proof in the text format of the reference
// implementation, so that your output can be compared with the provided
// file proof-for-leaf-95.txt.
func WriteProof(w io.Writer, p *Proof) error {
	var b strings.Builder
	fmt.Fprintf(&b, "leaf position: %d\n", p.Pos)
	fmt.Fprintf(&b, "leaf value: %q\n", p.Leaf)
	fmt.Fprintf(&b, "Hash values in proof:\n")
	for _, h := range p.Hashes {
		fmt.Fprintf(&b, "  %s\n", b64(h))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// WriteProofFile writes a proof to a file.
func WriteProofFile(name string, p *Proof) error {
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteProof(f, p)
}

// ReadProofFile reads back a proof written by WriteProofFile. Everything a
// verifier gets comes from outside, so this function trusts nothing: it
// reports an error rather than returning a half-parsed proof.
func ReadProofFile(name string) (*Proof, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	proof := &Proof{}
	scanner := bufio.NewScanner(f)
	line := 0
	for scanner.Scan() {
		text := scanner.Text()
		line++
		switch {
		case line == 1:
			pos, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(text, "leaf position:")))
			if err != nil {
				return nil, fmt.Errorf("line 1: bad leaf position: %v", err)
			}
			proof.Pos = pos
		case line == 2:
			value, err := strconv.Unquote(strings.TrimSpace(strings.TrimPrefix(text, "leaf value:")))
			if err != nil {
				return nil, fmt.Errorf("line 2: bad leaf value: %v", err)
			}
			proof.Leaf = []byte(value)
		case line == 3: // the "Hash values in proof:" header
		default:
			digest, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
			if err != nil {
				return nil, fmt.Errorf("line %d: bad hash: %v", line, err)
			}
			proof.Hashes = append(proof.Hashes, digest)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if line < 3 {
		return nil, fmt.Errorf("%s: truncated proof", name)
	}
	return proof, nil
}
