package main

import "fmt"

// A Merkle tree turns a whole list of values into a single digest, in a way
// that lets you prove afterwards that one particular value was in the list,
// without showing the rest of it.
//
// The construction is a binary tree. Its leaves are the hashes of the
// values; every internal node is the hash of its two children; the digest
// at the top is called the *root*. Publishing the root commits you to the
// entire list: changing any value, anywhere, changes the root.
//
//	                      root                       level 2
//	              /                  \
//	        h(h0|h1)                h(h2|h3)         level 1
//	        /      \                /      \
//	      h0        h1            h2        h3       level 0 (hashed leaves)
//	      |         |             |         |
//	    item0     item1         item2     item3
//
// Only the number of leaves is a power of two in this picture. Real lists
// are not that polite, so the level of hashed leaves is padded up to the
// next power of two -- see NewTree.

// PadValue is what we pad the level of hashed leaves with. Note that it is
// one byte long, while every real hash is 32 bytes long: this is deliberate,
// and question [Q3] of the README asks you why.
var PadValue = []byte{0}

// Tree holds the committed values and every level of the tree, bottom-up:
// levels[0] is the padded level of hashed leaves, and the last level holds
// the root alone. We keep all of it because a prover answers many queries
// on the same tree.
type Tree struct {
	values [][]byte
	levels [][][]byte
}

// Height returns the height of the tree: the number of hashes in a proof,
// and the number of times you halve the leaves to reach the root.
func (t *Tree) Height() int { return len(t.levels) - 1 }

// Root returns the digest that commits to the whole list.
func (t *Tree) Root() []byte {
	if len(t.levels) == 0 {
		return nil // the tree was not built
	}
	return t.levels[len(t.levels)-1][0]
}

// NewTree builds the tree that commits to the given values.
//
// [Task] Three steps:
//  1. hash every leaf with HashLeaf, into the bottom level;
//  2. pad that level with PadValue until its size is a power of two (it is
//     the *level* that is padded, not the list of values: you append
//     PadValue itself, not its hash);
//  3. build each level from the one below, by hashing consecutive pairs
//     with HashInternal, until a level holds a single digest.
//
// Keep every level in t.levels, bottom first. A list of one value gives a
// tree of height 0, whose root is the hash of that single leaf.
func NewTree(values [][]byte) *Tree {
	if len(values) == 0 {
		panic("a Merkle tree needs at least one value")
	}
	t := &Tree{values: values}
	// TODO: hash the leaves, pad, then fold the levels (section 5)
	return t
}

// Prove returns the proof that the value at position pos is in the tree.
//
// The proof is the list of *siblings* met on the way from the leaf to the
// root, bottom first. With them, and with the leaf itself, anybody can
// recompute the root: that is what RootFromProof does, and that is the
// whole point of the construction. Note what the proof does *not* contain:
// the other leaves. A tree of a million values is proved with twenty
// hashes.
//
//	            root                    proof for item2 = [h3, h(h0|h1)]
//	       /            \
//	 h(h0|h1)         h(h2|h3)          up from h2:
//	  /    \           /    \             its sibling is h3
//	h0      h1      [h2]     h3           then the sibling of h(h2|h3)
//
// [Task] Walk up the tree. At each level, append the sibling of the
// current position, then move to the parent. Two hints: the sibling of a
// position is the position with its lowest bit flipped, which Go writes
// pos^1; and the parent of a position is pos/2, pos>>1 in Go.
func (t *Tree) Prove(pos int) (*Proof, error) {
	if pos < 0 || pos >= len(t.values) {
		return nil, fmt.Errorf("no leaf at position %d", pos)
	}
	proof := &Proof{Leaf: t.values[pos], Pos: pos}
	// TODO: collect the siblings, bottom-up (section 6)
	return proof, nil
}
