<p align="center"><img src="https://raw.githubusercontent.com/go-newsgroups/brand/main/social/go-newsgroups.png" alt="go-newsgroups/par2" width="720"></p>

# par2

[![CI](https://github.com/go-newsgroups/par2/actions/workflows/ci.yml/badge.svg)](https://github.com/go-newsgroups/par2/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-newsgroups/par2.svg)](https://pkg.go.dev/github.com/go-newsgroups/par2)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

Pure-Go (CGO-free) parser, verifier and repairer for **PAR2** recovery sets —
the format behind the "AutoPAR" feature used to protect Usenet binaries.

- **Parse** concatenated `.par2` blobs into a `RecoverySet`, validating every
  packet's MD5 and skipping unknown or corrupt packets.
- **Verify** supplied files against the recovery set using the per-slice
  MD5+CRC32 checksums (hash based, independent of Reed-Solomon).
- **Repair** missing/damaged input slices from the available recovery slices via
  Reed-Solomon over GF(2^16).
- **Create** recovery slices for a set of input files (minimal generator side,
  enough for AutoPAR self-consistency and round-trip testing).

The Galois-field arithmetic core is reused from
[`github.com/go-erasure/reedsolomon`](https://github.com/go-erasure/reedsolomon)
(`GF16`, primitive polynomial `0x1100B`, generator `2`), the same field PAR2
uses. `CGO_ENABLED=0`, Go 1.26.4, stdlib only otherwise.

## Install

```sh
go get github.com/go-newsgroups/par2
```

## Verify and repair

```go
package main

import (
	"fmt"
	"os"

	"github.com/go-newsgroups/par2"
)

func main() {
	// Load the .par2 recovery data (one or more concatenated blobs).
	blob, _ := os.ReadFile("archive.par2")
	rs, err := par2.Parse(blob)
	if err != nil {
		panic(err)
	}

	// Collect the target files you have on disk.
	files := map[string][]byte{}
	for _, f := range rs.Files {
		if data, err := os.ReadFile(f.Name); err == nil {
			files[f.Name] = data
		}
	}

	// Hash-based verification.
	res, _ := rs.Verify(files)
	if res.Complete {
		fmt.Println("all files present and correct")
		return
	}
	fmt.Printf("damaged/missing; repairable=%v\n", res.Repairable)

	// Reed-Solomon repair.
	if res.Repairable {
		repaired, err := rs.Repair(files)
		if err != nil {
			panic(err)
		}
		for name, data := range repaired {
			_ = os.WriteFile(name, data, 0o644)
		}
		fmt.Println("repaired")
	}
}
```

## Compatibility caveat

`Verify` is hash based and is correct against real PAR2 files produced by any
tool.

`Repair` and `Create` implement the Vandermonde Reed-Solomon scheme described in
the PAR2 specification on top of the `go-erasure/reedsolomon` GF(2^16) field, and
are validated here by self-consistent round-trip (`Create` → damage → `Repair`
→ bytes match the originals). **Byte-exact interoperability with recovery data
produced by `par2cmdline` or QuickPar is NOT yet validated against those tools**
and is a planned follow-up (real-oracle validation).

## License

BSD-3-Clause. See [LICENSE](LICENSE).
