package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// These tests are the acceptance criteria of the practical. They pin the
// construction down to the byte, against the values published by the
// reference implementation, so that your tree is not merely *a* Merkle
// tree, but *the* Merkle tree everybody else in the world computes.

const referenceFile = "proof-for-leaf-95.txt"

// mustDecode turns base64 into bytes, or fails the test.
func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestHashVectors pins the two hash functions: the right prefix, on the
// right side, over the right bytes.
func TestHashVectors(t *testing.T) {
	if got, want := b64(HashLeaf([]byte("data item 95"))), "iAUobBePnj77p2KLbm24PsxF9DZsPkUcIKtnOyD5Btc="; got != want {
		t.Fatalf("HashLeaf: got %s, want %s", got, want)
	}
	left, right := HashLeaf([]byte("a")), HashLeaf([]byte("b"))
	if got, want := b64(HashInternal(left, right)), "0rDLPgvBhhNV3+1Z5i4DqS27TyUHtk2NijR02FatCE0="; got != want {
		t.Fatalf("HashInternal: got %s, want %s", got, want)
	}
	if len(HashLeaf(nil)) != 32 || len(HashInternal(nil, nil)) != 32 {
		t.Fatal("a SHA-256 digest is 32 bytes long")
	}
}

// TestHashOrderMatters checks that the two children of a node are not
// interchangeable. If they were, a proof would say "this leaf is in the
// tree" without saying *where*, and the position could be forged.
func TestHashOrderMatters(t *testing.T) {
	left, right := HashLeaf([]byte("a")), HashLeaf([]byte("b"))
	if bytes.Equal(HashInternal(left, right), HashInternal(right, left)) {
		t.Fatal("HashInternal(l, r) and HashInternal(r, l) must differ")
	}
}

// TestDomainSeparation is the reason for the "leaf:" and "node:" prefixes.
// Without them, the hash of the *leaf* whose content is two digests glued
// together would be the hash of the *node* having those two digests as
// children: the same 32 bytes would mean two different things, and a prover
// could pass one for the other.
func TestDomainSeparation(t *testing.T) {
	left, right := HashLeaf([]byte("a")), HashLeaf([]byte("b"))
	glued := append(append([]byte{}, left...), right...)
	if bytes.Equal(HashLeaf(glued), HashInternal(left, right)) {
		t.Fatal("a leaf hash must never collide with an internal node hash")
	}
}

// TestSmallTrees checks the shape of the tree on cases you can draw on
// paper, including the padding of a level that is not a power of two.
func TestSmallTrees(t *testing.T) {
	one := NewTree([][]byte{[]byte("a")})
	if one.Height() != 0 {
		t.Fatalf("a tree with a single leaf has height 0, got %d", one.Height())
	}
	if !bytes.Equal(one.Root(), HashLeaf([]byte("a"))) {
		t.Fatal("the root of a single-leaf tree is the hash of that leaf")
	}

	four := NewTree([][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")})
	if four.Height() != 2 {
		t.Fatalf("a tree with four leaves has height 2, got %d", four.Height())
	}
	if got, want := b64(four.Root()), "L1ob4NsLs4E/RzGY3PxAFtb+Auqnz3uQ23P43vLVdjA="; got != want {
		t.Fatalf("root of the four-leaf tree: got %s, want %s", got, want)
	}

	// Three leaves: the bottom level is padded to four with PadValue.
	three := NewTree([][]byte{[]byte("a"), []byte("b"), []byte("c")})
	if three.Height() != 2 {
		t.Fatalf("a tree with three leaves has height 2, got %d", three.Height())
	}
	if got, want := b64(three.Root()), "Zjy6lmnZof+G0EjnYcCBL9Sb+KRrMw4sQ3/st7nOdMM="; got != want {
		t.Fatalf("root of the three-leaf tree: got %s, want %s (is the level padded with PadValue itself?)", got, want)
	}
}

// TestPublishedRoot is the one that matters: the committed list must give
// the root that the reference implementation published.
func TestPublishedRoot(t *testing.T) {
	tree := NewTree(GenLeaves(NumLeaves))
	if tree.Height() != 10 {
		t.Fatalf("1000 leaves make a tree of height 10, got %d", tree.Height())
	}
	if got := b64(tree.Root()); got != PublishedRoot {
		t.Fatalf("root: got %s, want %s", got, PublishedRoot)
	}
}

// TestProofAgainstReference compares your proof for leaf 95, hash by hash
// and then byte by byte, with the file shipped with the practical.
func TestProofAgainstReference(t *testing.T) {
	want, err := ReadProofFile(referenceFile)
	if err != nil {
		t.Fatalf("cannot read %s: %v", referenceFile, err)
	}

	tree := NewTree(GenLeaves(NumLeaves))
	got, err := tree.Prove(95)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hashes) != len(want.Hashes) {
		t.Fatalf("proof of %d hashes, expected %d", len(got.Hashes), len(want.Hashes))
	}
	for i := range want.Hashes {
		if !bytes.Equal(got.Hashes[i], want.Hashes[i]) {
			t.Fatalf("hash %d of the proof: got %s, want %s", i, b64(got.Hashes[i]), b64(want.Hashes[i]))
		}
	}

	reference, err := os.ReadFile(referenceFile)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteProof(&buf, got); err != nil {
		t.Fatal(err)
	}
	if buf.String() != string(reference) {
		t.Fatalf("the proof file differs from %s:\n--- got ---\n%s--- want ---\n%s", referenceFile, buf.String(), reference)
	}
}

// TestProveAndVerify is one full round trip, on one leaf.
func TestProveAndVerify(t *testing.T) {
	tree := NewTree(GenLeaves(NumLeaves))
	proof, err := tree.Prove(683)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Hashes) != 10 {
		t.Fatalf("a proof in a tree of height 10 has 10 hashes, got %d", len(proof.Hashes))
	}
	if !bytes.Equal(RootFromProof(proof), tree.Root()) {
		t.Fatal("the proof does not lead back to the root of the tree")
	}
	if !Verify(proof, mustDecode(t, PublishedRoot)) {
		t.Fatal("the proof does not verify against the published root")
	}
	if string(proof.Leaf) != "data item 683" {
		t.Fatalf("the proof carries the wrong leaf: %q", proof.Leaf)
	}
}

// TestProveOutOfRange checks that a prover refuses positions that are not
// in the list -- in particular the padding, which commits to nothing.
func TestProveOutOfRange(t *testing.T) {
	tree := NewTree(GenLeaves(NumLeaves))
	for _, pos := range []int{-1, NumLeaves, NumLeaves + 20, 1 << 20} {
		if _, err := tree.Prove(pos); err == nil {
			t.Fatalf("Prove(%d) should have failed", pos)
		}
	}
}

// TestProofFileRoundTrip checks the format written and read back.
func TestProofFileRoundTrip(t *testing.T) {
	tree := NewTree(GenLeaves(NumLeaves))
	proof, err := tree.Prove(742)
	if err != nil {
		t.Fatal(err)
	}
	name := t.TempDir() + "/proof.txt"
	if err := WriteProofFile(name, proof); err != nil {
		t.Fatal(err)
	}
	back, err := ReadProofFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Hashes) != 10 {
		t.Fatalf("a proof in a tree of height 10 has 10 hashes, got %d", len(back.Hashes))
	}
	if back.Pos != proof.Pos || !bytes.Equal(back.Leaf, proof.Leaf) || len(back.Hashes) != len(proof.Hashes) {
		t.Fatalf("round trip changed the proof: %+v", back)
	}
	if !Verify(back, tree.Root()) {
		t.Fatal("the proof read back does not verify")
	}
}

// TestEveryLeafIsProvable checks the prover on the whole list, not just on
// one lucky position. A tree of 1000 leaves has left children and right
// children, and one of the two is easy to get wrong.
//
// [Opt] Write this test: build the tree once, then for every position of
// the committed list, produce the proof and check that it verifies against
// the published root and that it carries the expected leaf value. Check
// also that every proof has the same length, and say in a comment why that
// length is 10 and not 1000.
func TestEveryLeafIsProvable(t *testing.T) {
	t.Skip("TODO: write this test (section 8)")
}

// TestTamperingIsDetected is the security property. A proof that has been
// touched anywhere must not verify: this is what stops a full node from
// convincing a light client that a payment is in a block when it is not.
//
// [Opt] Write this test. Start from a valid proof, and check that Verify
// returns false after each of the following, taken one at a time:
//   - changing one byte of the leaf value;
//   - changing one byte of one of the hashes of the proof;
//   - claiming another position for the same leaf;
//   - removing a hash from the proof, or adding one.
//
// Be careful to start again from a fresh proof for each case, and beware of
// Go slices: two slices can share the same underlying array, so copy before
// you modify.
func TestTamperingIsDetected(t *testing.T) {
	t.Skip("TODO: write this test (section 8)")
}

// TestVerifierRejectsGarbage checks that the reader does not hand a
// half-parsed proof to the verifier.
func TestVerifierRejectsGarbage(t *testing.T) {
	name := t.TempDir() + "/garbage.txt"
	for _, content := range []string{
		"",
		"leaf position: x\n",
		"leaf position: 1\nleaf value: unquoted\nHash values in proof:\n",
		"leaf position: 1\nleaf value: \"a\"\nHash values in proof:\n  not-base64!!\n",
	} {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadProofFile(name); err == nil {
			t.Fatalf("reading %q should have failed", strings.ReplaceAll(content, "\n", "\\n"))
		}
	}
}
