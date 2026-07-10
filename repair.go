package par2

import (
	"crypto/md5"
	"encoding/binary"
	"sort"

	"github.com/go-erasure/reedsolomon"
)

// field is the shared GF(2^16) arithmetic core (primitive poly 0x1100B,
// generator 2), reused from go-erasure/reedsolomon for PAR2 compatibility.
var field = reedsolomon.NewGF16()

// sliceWords is the number of big-endian uint16 words in a slice of the given
// byte size (an odd byte is promoted to a zero-padded word).
func sliceWords(sliceSize uint64) int { return int((sliceSize + 1) / 2) }

// bytesToWords reads b as big-endian uint16 words, zero-padding to w words.
func bytesToWords(b []byte, w int) []uint16 {
	out := make([]uint16, w)
	for i := 0; i < w; i++ {
		hi := i * 2
		if hi >= len(b) {
			break
		}
		var v uint16 = uint16(b[hi]) << 8
		if hi+1 < len(b) {
			v |= uint16(b[hi+1])
		}
		out[i] = v
	}
	return out
}

// wordsToBytes writes words as big-endian bytes.
func wordsToBytes(words []uint16) []byte {
	out := make([]byte, len(words)*2)
	for i, v := range words {
		binary.BigEndian.PutUint16(out[i*2:], v)
	}
	return out
}

// coef returns the recovery matrix coefficient for input block index i under
// recovery exponent e: (base_i)^e where base_i = generator^i, i.e. g^(i*e).
func coef(i int, e uint32) uint16 {
	return field.Exp(i * int(e))
}

// Create builds recovery slices (exponents 0..recoveryCount-1) for the given
// input files, returning a RecoverySet suitable for serialization or for
// round-trip testing.
func Create(sliceSize uint64, files map[string][]byte, recoveryCount int) (*RecoverySet, error) {
	if sliceSize == 0 {
		return nil, ErrOddSliceSize
	}

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	rs := &RecoverySet{SliceSize: sliceSize, Creator: "go-newsgroups/par2"}
	w := sliceWords(sliceSize)

	var blocks [][]uint16 // all input blocks, in file then slice order
	for _, name := range names {
		data := files[name]
		spec := FileSpec{
			ID:      md5.Sum([]byte(name)),
			Name:    name,
			Length:  uint64(len(data)),
			FullMD5: md5.Sum(data),
		}
		n := numSlices(spec.Length, sliceSize)
		for s := 0; s < n; s++ {
			chunk := sliceOf(data, s, sliceSize)
			sum := md5.Sum(chunk)
			spec.Slices = append(spec.Slices, SliceChecksum{MD5: sum, CRC32: crc32IEEE(chunk)})
			blocks = append(blocks, bytesToWords(chunk, w))
		}
		rs.Files = append(rs.Files, spec)
	}

	for e := 0; e < recoveryCount; e++ {
		acc := make([]uint16, w)
		for i, blk := range blocks {
			c := coef(i, uint32(e))
			for k := 0; k < w; k++ {
				acc[k] ^= field.Mul(blk[k], c)
			}
		}
		rs.Recovery = append(rs.Recovery, RecoverySlice{
			Exponent: uint32(e),
			Data:     wordsToBytes(acc),
		})
	}
	return rs, nil
}

// Repair reconstructs missing/damaged input slices from the available recovery
// slices via Reed-Solomon over GF(2^16), returning the repaired file contents
// keyed by file name. It errors if the set is not repairable.
func (rs *RecoverySet) Repair(files map[string][]byte) (map[string][]byte, error) {
	vr, err := rs.Verify(files)
	if err != nil {
		return nil, err
	}

	missing := map[int]bool{}
	for _, fstat := range vr.Files {
		for _, g := range fstat.MissingSlices {
			missing[g] = true
		}
	}

	w := sliceWords(rs.SliceSize)

	// Gather all blocks; unknown ones get a nil placeholder.
	type blockRef struct {
		known []uint16 // nil if unknown
		file  int
		slice int
	}
	var refs []blockRef
	global := 0
	for fi, f := range rs.Files {
		n := numSlices(f.Length, rs.SliceSize)
		data := files[f.Name] // absent files yield nil, but all their slices are "missing"
		for s := 0; s < n; s++ {
			if missing[global] {
				refs = append(refs, blockRef{known: nil, file: fi, slice: s})
			} else {
				refs = append(refs, blockRef{known: bytesToWords(sliceOf(data, s, rs.SliceSize), w), file: fi, slice: s})
			}
			global++
		}
	}

	var unknowns, knowns []int // indices into refs
	for i, r := range refs {
		if r.known == nil {
			unknowns = append(unknowns, i)
		} else {
			knowns = append(knowns, i)
		}
	}
	u := len(unknowns)

	if u > len(rs.Recovery) {
		return nil, ErrNotRepairable
	}

	if u > 0 {
		// Select the u recovery slices with the smallest exponents.
		rec := append([]RecoverySlice(nil), rs.Recovery...)
		sort.Slice(rec, func(a, b int) bool { return rec[a].Exponent < rec[b].Exponent })
		rec = rec[:u]

		// Build the u x u coefficient matrix A and the u x w RHS matrix B.
		a := make([][]uint16, u)
		b := make([][]uint16, u)
		for r := 0; r < u; r++ {
			e := rec[r].Exponent
			a[r] = make([]uint16, u)
			for c := 0; c < u; c++ {
				a[r][c] = coef(unknowns[c], e)
			}
			rhs := bytesToWords(rec[r].Data, w)
			for _, ki := range knowns {
				c := coef(ki, e)
				kb := refs[ki].known
				for k := 0; k < w; k++ {
					rhs[k] ^= field.Mul(kb[k], c)
				}
			}
			b[r] = rhs
		}

		if !gaussJordan(a, b) {
			return nil, ErrNotRepairable
		}
		// b now holds the solved unknown blocks (row r == unknowns[r]).
		for r, idx := range unknowns {
			refs[idx].known = b[r]
		}
	}

	// Reconstruct each file from its (now complete) blocks.
	out := map[string][]byte{}
	blocksByFile := map[int][][]uint16{}
	for _, r := range refs {
		blocksByFile[r.file] = append(blocksByFile[r.file], r.known)
	}
	for fi, f := range rs.Files {
		var buf []byte
		for _, blk := range blocksByFile[fi] {
			bb := wordsToBytes(blk)
			// A block holds ceil(SliceSize/2) words; an odd slice size leaves a
			// trailing pad byte that must not bleed into the next slice.
			if uint64(len(bb)) > rs.SliceSize {
				bb = bb[:rs.SliceSize]
			}
			buf = append(buf, bb...)
		}
		if uint64(len(buf)) > f.Length {
			buf = buf[:f.Length]
		}
		out[f.Name] = buf
	}
	return out, nil
}

// gaussJordan solves a*x = b in place over GF(2^16), reducing a to the identity
// so that b holds x on return. It returns false if a is singular.
func gaussJordan(a, b [][]uint16) bool {
	n := len(a)
	for p := 0; p < n; p++ {
		// Find a non-zero pivot in column p at or below row p.
		pr := -1
		for r := p; r < n; r++ {
			if a[r][p] != 0 {
				pr = r
				break
			}
		}
		if pr < 0 {
			return false
		}
		a[p], a[pr] = a[pr], a[p]
		b[p], b[pr] = b[pr], b[p]

		// Normalise the pivot row so a[p][p] == 1.
		inv := field.Div(1, a[p][p])
		for c := 0; c < n; c++ {
			a[p][c] = field.Mul(a[p][c], inv)
		}
		for k := 0; k < len(b[p]); k++ {
			b[p][k] = field.Mul(b[p][k], inv)
		}

		// Eliminate column p from every other row.
		for r := 0; r < n; r++ {
			if r == p || a[r][p] == 0 {
				continue
			}
			f := a[r][p]
			for c := 0; c < n; c++ {
				a[r][c] ^= field.Mul(f, a[p][c])
			}
			for k := 0; k < len(b[r]); k++ {
				b[r][k] ^= field.Mul(f, b[p][k])
			}
		}
	}
	return true
}
