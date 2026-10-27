package main

import (
	"encoding/base64"
)

// A hash function takes a message of any length and returns a short,
// fixed-size digest -- 32 bytes for SHA-256. What makes it useful here is
// that it is *collision resistant*: nobody knows how to find two different
// messages with the same digest. So a digest can stand for its message: if
// you and I agree on a digest, we agree on the data behind it.
//
// That is the whole idea of a commitment, and the whole idea of a
// blockchain. The rest of this practical is one construction built on top
// of it.

// The prefixes below implement *domain separation*. A leaf hash and an
// internal node hash are computed by the same function, over different
// kinds of input, so we tag the input to keep the two domains apart. The
// question [Q2] of the README asks you what goes wrong without them --
// think about it before you read the answer anywhere else.
var (
	LeafPrefix = []byte("leaf:")
	NodePrefix = []byte("node:")
)

// HashLeaf returns the digest of a leaf of the tree.
//
// [Task] Return sha256(LeafPrefix || leaf). Have a look at the
// documentation of the crypto/sha256 package: the shortest way is
// sha256.Sum256, which takes a slice and returns an array of 32 bytes that
// you can turn back into a slice with sum[:].
func HashLeaf(leaf []byte) []byte {
	return nil // TODO: hash the leaf, with its prefix (section 4)
}

// HashInternal returns the digest of an internal node of the tree, from the
// digests of its two children.
//
// [Task] Return sha256(NodePrefix || left || right).
func HashInternal(left, right []byte) []byte {
	return nil // TODO: hash the two children, with the node prefix (section 4)
}

// b64 renders a digest the way the reference implementation does, so that
// you can compare your output with the provided proof file.
func b64(digest []byte) string {
	return base64.StdEncoding.EncodeToString(digest)
}
