package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
)

// The story: a light client, say a wallet on a phone, keeps only the
// headers of the blocks. A header does not hold the transactions of its
// block -- it holds one 32-byte root that commits to them. To show that a
// payment is in the block, a full node sends the transaction and a handful
// of hashes, and the wallet checks in a few microseconds that it is in a
// block it never stored. That is a Merkle proof, and by the end of this
// practical you will have written both sides of it.
//
//	go run . root          print the root of the committed tree
//	go run . prove 683     write the proof for leaf 683 in merkle_proof.txt
//	go run . verify 683    check that proof against the published root

const (
	// NumLeaves is the size of the committed list.
	NumLeaves = 1000

	// ProofFile is where the prover writes, and the verifier reads.
	ProofFile = "merkle_proof.txt"

	// PublishedRoot is the commitment to the list below. It is the value
	// published by the reference implementation of this exercise
	// (Stanford CS251, programming project 1): if your tree is correct,
	// you will compute exactly this root, byte for byte.
	PublishedRoot = "1qIbsvuF6FrhNjMD4p06srUye6G4FfFINDDkNfKUpTs="
)

// GenLeaves returns the committed list. It never changes, so the root never
// changes either.
func GenLeaves(n int) [][]byte {
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("data item %d", i))
	}
	return leaves
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: go run . root | prove <leaf> | verify [leaf]")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	published, err := base64.StdEncoding.DecodeString(PublishedRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	switch os.Args[1] {

	case "root":
		tree := NewTree(GenLeaves(NumLeaves))
		fmt.Printf("I generated %d leaves for a Merkle tree of height %d.\n", NumLeaves, tree.Height())
		fmt.Printf("  my root:        %s\n", b64(tree.Root()))
		fmt.Printf("  published root: %s\n", PublishedRoot)
		if b64(tree.Root()) == PublishedRoot {
			fmt.Println("They match: my tree commits to the published list.")
		} else {
			fmt.Println("They differ: something in NewTree is not right yet.")
			os.Exit(1)
		}

	case "prove":
		if len(os.Args) < 3 {
			usage()
		}
		pos, err := strconv.Atoi(os.Args[2])
		if err != nil {
			usage()
		}
		tree := NewTree(GenLeaves(NumLeaves))
		fmt.Printf("I generated %d leaves for a Merkle tree of height %d.\n", NumLeaves, tree.Height())
		proof, err := tree.Prove(pos)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := WriteProofFile(ProofFile, proof); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("I generated a Merkle proof for leaf #%d in file %s\n", pos, ProofFile)

	case "verify":
		proof, err := ReadProofFile(ProofFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(os.Args) > 2 {
			pos, err := strconv.Atoi(os.Args[2])
			if err != nil {
				usage()
			}
			if pos != proof.Pos {
				fmt.Fprintf(os.Stderr, "the proof is for leaf #%d, not #%d\n", proof.Pos, pos)
				os.Exit(1)
			}
		}
		if !Verify(proof, published) {
			fmt.Fprintln(os.Stderr, "VERIFICATION FAILED: this proof does not lead to the published root")
			os.Exit(1)
		}
		fmt.Printf("I verified the Merkle proof: leaf #%d in the committed tree is %q.\n", proof.Pos, proof.Leaf)

	default:
		usage()
	}
}
