# Merkle trees — proving one thing without showing everything [2h]

**Outline.** You will implement a Merkle tree in Go: the hashing that binds
it together, the construction of the tree from a list of values, the
generation of a *proof* that one value is in that list, and the verification
of such a proof against a published commitment. If you have time left, you
will then try to break it.

This practical follows [programming project
1](https://cs251.stanford.edu/hw/proj1.pdf) of Stanford's *CS251:
Cryptocurrencies and Blockchain Technologies*, transposed to Go — the
language we use for the whole course. The committed list, the hash
construction and the published root are the same as in the reference
implementation, so a correct Go implementation produces *exactly* the same
root and the same proof file, byte for byte. The provided file
`proof-for-leaf-95.txt` comes straight from it, and the tests compare your
output with it.

This is the first practical of the course, so it starts from scratch: no
network, no consensus, no blockchain. Just a hash function, and what you can
build with it.

You will have to complete all the items marked by **[Task]**. Items marked
**[Opt]** are optional, and questions marked **[Q]** are to be answered in
writing.

## 1. Committing to a list [10']

Alice receives a payment in bitcoins, on the wallet of her phone. Before
she hands over what she sold, she wants to check that the transaction is in
a block of the chain. But a phone cannot store the chain: it weighs hundreds
of gigabytes, and grows every ten minutes.

So the wallet is a **light client**: it downloads only the *headers* of the
blocks, 80 bytes each. A header does not contain the transactions of its
block, a few thousand of them; it holds **32 bytes** that commit to all of
them, a Merkle root. To prove that the transaction is in the block, a full
node sends it to the wallet with about twelve hashes; the wallet recomputes
the root from them and compares it with the one in the header. It never held
the block, and it still cannot be fooled: it does not have to trust the full
node that answers. Bitcoin calls this *simplified payment verification*
(SPV).

That single trick — commit to a lot of data with a small digest, then prove
things about the data piece by piece — is everywhere:

- **Ethereum** commits to its whole state, and to the receipts of every
  transaction, with the same kind of tree;
- **Certificate Transparency** logs, **git**, **IPFS** and BitTorrent all
  name their content by a hash tree.

The ingredient is *collision resistance*: nobody knows how to produce two
different inputs with the same SHA-256 digest. So a digest can stand for its
input — if we agree on the digest, we agree on the data.

**[Q1]** Suppose SHA-256 were broken tomorrow, and that you could produce
two different values with the same digest, at will. Describe concretely what
you could do to Alice's wallet.

## 2. Getting started [15']

Install Go (>= 1.21) following the official instructions:
<https://go.dev/dl/>, then check the installation and run the tests:

```sh
go version
go test
```

Everything should *compile* at this point and most tests should fail. Your
job is to fill the `// TODO` gaps, in the order of the sections below, until
they all pass. Two tests are skipped: those of the optional section 8,
which you write yourself.

`go test` is the test runner of Go. It compiles the package, together with
its files whose name ends in `_test.go` (here, `merkle_test.go`), and runs
every function whose name starts with `Test`, such as `TestSmallTrees`. A
test fails when it calls `t.Error` or `t.Fatal`, and is skipped when it calls
`t.Skip`. Two options are used throughout this practical:

- `-v` (verbose) prints the name and the outcome of every test, `PASS`,
  `FAIL` or `SKIP`, together with the messages of the failing ones; without
  it, `go test` prints only the failures and a one-line summary;
- `-run 'TestA|TestB'` runs only the tests whose name matches the given
  regular expression (here, `TestA` or `TestB`), so that each section
  checks the functions it asks you to write and nothing else.

For instance, `go test -run TestSmallTrees -v` runs the single test
`TestSmallTrees` and reports it in detail.

If Go is new to you, the [tour of Go](https://go.dev/tour/welcome/1) is
fifteen minutes well spent — the sections on slices and on methods are the
ones you need here. One Go-specific trap, worth knowing before you meet it:
a `[]byte` is a *view* on an array, so two slices can share the same memory,
and `append` may or may not allocate. When in doubt, copy explicitly with
`append([]byte{}, b...)`.

## 3. Tour of the provided code [5']

	hash.go          the two hash functions, and their domain separation
	tree.go          the tree: construction, root, proof generation
	proof.go         the proof: verification, and its file format
	main.go          the command-line prover and verifier
	merkle_test.go   the acceptance tests

	proof-for-leaf-95.txt   a reference proof, from the original project

The committed list is fixed once and for all in `GenLeaves`: the thousand
strings `data item 0` … `data item 999`. It never changes, so its root never
changes, and that root is published in `main.go` as `PublishedRoot`.

## 4. Hashing, and why there are two prefixes [15']

Everything is built from one hash function used in two different ways:

	HashLeaf(v)          = sha256("leaf:" || v)
	HashInternal(l, r)   = sha256("node:" || l || r)

The prefixes are not decoration: they implement **domain separation**, so
that a digest computed for a leaf can never be mistaken for a digest
computed for an internal node.

**[Task]** Implement `HashLeaf` and `HashInternal` in `hash.go`.

At any time, you can validate `HashLeaf` and `HashInternal` by running the
following command:

```sh
go test -run 'TestHash|TestDomain' -v
```

**[Q2]** Look at the test `TestDomainSeparation`: it builds a leaf whose
*content* is the concatenation of two digests. Without the prefixes, what
would the hash of that leaf be equal to? Explain, in that setting, how a
dishonest prover could prove that a value is in the tree when it is not.
(This is a real attack on real trees; it has a name, look it up.)

## 5. Building the tree [35']

The tree is built from the bottom up. The bottom level holds the hashes of
the values; each level above holds the hashes of consecutive *pairs* of the
level below; the top level holds one digest, the **root**.

	                      root                       level 2
	              /                  \
	        h(h0|h1)                h(h2|h3)         level 1
	        /      \                /      \
	      h0        h1            h2        h3       level 0
	      |         |             |         |
	    item0     item1         item2     item3

Pairs need an even number of nodes at every level, so the bottom level is
padded up to the next power of two — with the constant `PadValue`, which is
a single zero byte.

**[Task]** Implement `NewTree` in `tree.go`. Watch the padding: you append
`PadValue` itself to the *level*, you do not add a value to the list and
hash it.

<details>
<summary><b>help me</b></summary>

This help walks you through `NewTree` one small step at a time, and explains
the bits of Go you need along the way. Write each piece in `tree.go`, at the
`// TODO` line of `NewTree`, in the order given.

**Step 0: read the types.** In Go, `[]byte` is a *slice of bytes*: a
sequence of bytes of any length. A value of the list is a `[]byte`, and so is
a digest (32 bytes long). Then:

- `[][]byte` is a slice of `[]byte`: a list of byte sequences. This is the
  type of the argument `values`, and of each *level* of the tree, the list
  of the digests at one height;
- `[][][]byte` is a slice of levels: this is `t.levels`, the whole tree.
  `t.levels[0]` is the bottom level, `t.levels[1]` the one above, and so on.

The first lines of `NewTree` are given: they refuse an empty list and create
`t`, a tree whose `values` field holds the list and whose `levels` field is
still empty. Your job is to fill `t.levels`.

**Step 1: declare the bottom level.** Declare a variable that will hold the
current level, empty for now:

```go
var level [][]byte
```

`var name type` declares a variable; an empty slice needs no other
initialization. (Go also has the short form `name := value`, which declares
the variable and guesses its type from the value; you will use it below.)

**Step 2: hash every value into it.** Go has a single loop keyword, `for`.
To go through a slice, write:

```go
for _, v := range values {
	// v is each value of the list in turn
}
```

`range` gives two things at each turn: the position and the element. We do
not need the position, so we throw it away with `_`. Inside the loop, add the
hash of `v` at the end of `level`:

```go
level = append(level, HashLeaf(v))
```

`append` returns the extended slice; do not forget to assign it back to
`level`, otherwise the result is lost.

**Step 3: find the padded size.** We want the smallest power of two that is
greater than or equal to `len(level)`. Start from 1 and double until it is
large enough. A `for` with only a condition is Go's *while* loop:

```go
size := 1
for size < len(level) {
	size *= 2
}
```

**Step 4: pad.** Append `PadValue` to `level` until its length reaches
`size`. This is again a *while* loop, whose body is a single `append`: write
it yourself. Mind the warning of the task: you append `PadValue` itself, not
`HashLeaf(PadValue)`.

**Step 5: store the bottom level.** The bottom level is complete; add it to
the tree:

```go
t.levels = append(t.levels, level)
```

**Step 6: build the level above.** Suppose `level` holds `[a, b, c, d]`. The
level above is `[HashInternal(a, b), HashInternal(c, d)]`. To pair the
elements, go through the positions two by two with the classic three-part
`for` (start; condition; step):

```go
var next [][]byte
for i := 0; i < len(level); i += 2 {
	next = append(next, HashInternal(level[i], level[i+1]))
}
```

`level[i]` is the element at position `i` (positions start at 0). Since the
length of `level` is a power of two, `level[i+1]` always exists, except when
the level has a single element, and then we stop (next step).

*Check:* `next` is half the length of `level`.

**Step 7: repeat up to the root.** Step 6 must be repeated as long as the
current level holds more than one digest. Wrap it in a *while* loop:

```go
for len(level) > 1 {
	// step 6: compute next from level
	// add next to t.levels (as in step 5)
	// then climb: level = next
}
```

Do not forget the last line, `level = next`: without it, `level` never
shrinks and the loop never ends. When the loop stops, the last element of
`t.levels` holds a single digest, and that is what `Root()` returns.

*Check:* for 1000 values, `t.levels` has 11 levels, of sizes 1024, 512, …,
2, 1, so `Height()` returns 10. For a single value, the loop does not run at
all: the tree has height 0, and its root is `HashLeaf` of that value, as the
comment of `NewTree` requires.

**Step 8: test.** Run the command below. If a test fails, print what you
build: `fmt.Println(len(level))` inside a loop shows the size of each level
(the package `fmt` is already imported in `tree.go`); remove the line once
you are done.

</details>

At any time, you can validate `NewTree` by running the following command:

```sh
go test -run 'TestSmallTrees|TestPublishedRoot' -v
```

**[Q3]** `PadValue` is one byte long, while every real digest is 32 bytes
long. Explain why a padding entry can therefore never be confused with the
hash of a real subtree — and why padding with 32 zero bytes instead would
deserve a second thought.

## 6. Proving [25']

A proof that the value at position `pos` is in the tree is the list of the
**siblings** met on the way up from the leaf to the root, bottom first.

	              root                    proof for item2 = [h3, h(h0|h1)]
	         /            \
	   h(h0|h1)         h(h2|h3)          from h2, going up:
	    /    \           /    \             the sibling of h2 is h3,
	  h0      h1      [h2]     h3           then the sibling of h(h2|h3).

**[Task]** Implement `Tree.Prove` in `tree.go`. The sibling of a position is
`pos^1` (flip the lowest bit), and the parent of a position is `pos>>1`.

At any time, you can validate `Tree.Prove` by running the following
commands:

```sh
go test -run 'TestProofAgainstReference|TestProveOutOfRange' -v
go run . prove 95
diff merkle_proof.txt proof-for-leaf-95.txt
```

`go run .` compiles the package of the current directory (`.`) into a
temporary program and runs it at once, with the words that follow as its
arguments. Here, the program is the command-line prover and verifier of
`main.go`: `go run . prove 95` builds the tree, and writes the proof for the
value at position 95 to the file `merkle_proof.txt`. The `diff` must be
empty: you have just reproduced the reference proof.

**[Q4]** The tree has 1000 leaves and height 10. How many hashes does a
proof contain? And for a list of one million values? Give the general
formula. Compare with committing to the list by hashing it in one go: what
must a prover send then to show that one value is in the list?

## 7. Verifying [15']

The verifier is the interesting half, because it is the one that runs in the
light client, on the phone. It holds 32 bytes of committed state and a
proof, and nothing else: no tree, no list, no trust in whoever sent the
proof.

It recomputes the root by climbing back up, combining what it holds with
each hash of the proof. The only delicate point is the *order* of the two
children, since `HashInternal(a, b)` and `HashInternal(b, a)` are different
digests — and the order is dictated by the position: an even position is a
left child, an odd position is a right child.

**[Task]** Implement `RootFromProof` in `proof.go`.

<details>
<summary><b>help me</b></summary>

Keep two variables: the digest you hold, and its position. The digest
starts as `HashLeaf(p.Leaf)`, not as the leaf itself: the bottom level of
the tree holds hashes, not values. Then go through `p.Hashes` with a
`for … range` loop, as in `NewTree`. At each step, if the position is even
(`pos%2 == 0`), what you hold is the left child, and the new digest is
`HashInternal(held, sibling)`; otherwise it is the right child, and the
order is reversed. Then move up with `pos >>= 1`. When the loop ends, the
digest you hold is the root.

</details>

At any time, you can validate `RootFromProof` by running the following
commands:

```sh
go test -run 'TestProveAndVerify|TestProofFileRoundTrip' -v
go run . root
go run . prove 683
go run . verify 683
```

`go run . root` prints the root of your tree next to `PublishedRoot`, the
root published in `main.go`: the two must be equal, byte for byte, which
means that your tree agrees with the reference implementation of the
original project, and with everybody else's. This published root is the
only thing the verifier trusts: `go run . verify 683` reads the proof from
`merkle_proof.txt`, recomputes a root from it with `RootFromProof`, and
accepts the proof only if that root is the published one.

**[Q5]** Suppose `HashInternal` ignored the order of its arguments, for
instance by sorting them. What could a prover then claim about the position
of a leaf? Why does that matter for a light client, given that the first
transaction of a Bitcoin block is special: it is the *coinbase*, which mints
the reward of the miner?

**[Q6]** `Verify` refuses any proof longer than `MaxHeight` *before* hashing
anything. Against what kind of attack does that guard, and why is it the
verifier's job rather than the prover's?

## 8. Breaking it (optional)

A construction is only as convincing as the attacks it survives. If you
have time left, play the adversary.

**[Opt]** Complete `TestEveryLeafIsProvable` in `merkle_test.go`: every
position of the list, not just a lucky one, must produce a proof that
verifies against the published root.

**[Opt]** Complete `TestTamperingIsDetected`: a proof modified anywhere —
the leaf, one hash, the claimed position, the length of the proof — must be
rejected.

At any time, you can validate both tests, and the rest of the practical, by
running the following command:

```sh
go test -v
```

**[Opt]** Do it by hand, as the original project asks: generate a proof,
change one character in `merkle_proof.txt`, and run the verifier again.

```sh
go run . prove 683
# now edit merkle_proof.txt: change one character
go run . verify 683
```

## What we simplified

- **nothing is signed, and there is no chain**: the light client is the
  motivation, not the code. The leaf is a string, not a transaction with a
  signature;
- **only membership is proved**: a full node can show Alice's wallet that a
  payment *is* in a block, but not that it is *not*, so the wallet cannot
  tell an absent transaction from a hidden one. Absence can be proved if the
  leaves are sorted: to show that `x` is not in the list, give the proofs of
  two leaves `a < x < b` at adjacent positions `i` and `i+1`; nothing can
  sit between them. The verifier still has to trust that the list was sorted
  when it was committed;
- **the root does not state the size of the list**: a verifier here learns
  it from the length of the proof and from the padding convention. Serious
  designs commit to the size explicitly;
- **no second-preimage hardening beyond the prefixes**, no salting of the
  leaves, and the tree is built in memory, in one go, for a thousand values.

## Validation checklist

Hand the practical in when:

- [ ] all the `[Task]` gaps in `hash.go`, `tree.go` and `proof.go` are
      filled;
- [ ] `go test -v` passes (the two tests of section 8 are skipped unless
      you wrote them);
- [ ] `go run . root` prints the published root;
- [ ] `go run . prove 95` produces a file identical to
      `proof-for-leaf-95.txt`;
- [ ] `go run . verify 95` accepts it;
- [ ] your report answers the `[Q]` questions (a few sentences each), and
      is handed in with your code.

Congratulations: you have implemented the data structure that lets a
32-byte commitment stand for a list of any size, and lets anybody check one
element of it with a handful of hashes. Every blockchain in existence uses
it, at least once per block.
