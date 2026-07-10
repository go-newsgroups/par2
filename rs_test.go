package par2

import (
	"bytes"
	"crypto/md5"
	"errors"
	"testing"
)

func TestVerifyComplete(t *testing.T) {
	files := map[string][]byte{
		"a.bin": bytes.Repeat([]byte{0xAB}, 10),
		"b.bin": bytes.Repeat([]byte{0xCD}, 8),
	}
	rs, err := Create(4, files, 2)
	if err != nil {
		t.Fatal(err)
	}
	vr, err := rs.Verify(files)
	if err != nil {
		t.Fatal(err)
	}
	if !vr.Complete || !vr.Repairable {
		t.Fatalf("Complete=%v Repairable=%v", vr.Complete, vr.Repairable)
	}
	for _, fs := range vr.Files {
		if !fs.Present || fs.Damaged || len(fs.MissingSlices) != 0 {
			t.Errorf("file %s: %+v", fs.Name, fs)
		}
	}
}

func TestVerifyMissingFile(t *testing.T) {
	files := map[string][]byte{
		"a.bin": bytes.Repeat([]byte{1}, 8), // 2 slices
		"b.bin": bytes.Repeat([]byte{2}, 4), // 1 slice
	}
	rs, _ := Create(4, files, 3)
	delete(files, "a.bin")
	vr, _ := rs.Verify(files)
	if vr.Complete {
		t.Fatal("should not be complete")
	}
	var a FileStatus
	for _, fs := range vr.Files {
		if fs.Name == "a.bin" {
			a = fs
		}
	}
	if a.Present || len(a.MissingSlices) != 2 {
		t.Fatalf("a: %+v", a)
	}
	if !vr.Repairable { // 2 missing <= 3 recovery
		t.Fatal("should be repairable")
	}
}

func TestVerifyDamagedSlice(t *testing.T) {
	orig := bytes.Repeat([]byte{9}, 10)
	files := map[string][]byte{"a.bin": orig}
	rs, _ := Create(4, files, 1)
	corrupt := append([]byte(nil), orig...)
	corrupt[5] ^= 0xFF
	vr, _ := rs.Verify(map[string][]byte{"a.bin": corrupt})
	fs := vr.Files[0]
	if !fs.Damaged || len(fs.MissingSlices) != 1 || fs.MissingSlices[0] != 1 {
		t.Fatalf("fs = %+v", fs)
	}
}

func TestVerifyWrongLength(t *testing.T) {
	orig := bytes.Repeat([]byte{9}, 8)
	files := map[string][]byte{"a.bin": orig}
	rs, _ := Create(4, files, 2)
	long := append(append([]byte(nil), orig...), 0xFF)
	vr, _ := rs.Verify(map[string][]byte{"a.bin": long})
	if vr.Complete || !vr.Files[0].Damaged {
		t.Fatalf("expected damaged, got %+v", vr.Files[0])
	}
}

func TestVerifyNoSliceSize(t *testing.T) {
	rs := &RecoverySet{}
	if _, err := rs.Verify(nil); !errors.Is(err, ErrNoSliceSize) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyCRCMismatch(t *testing.T) {
	// MD5 correct but CRC32 wrong: hits the CRC comparison branch.
	data := bytes.Repeat([]byte{7}, 4)
	chunk := sliceOf(data, 0, 4)
	rs := &RecoverySet{
		SliceSize: 4,
		Files: []FileSpec{{
			Name:   "a.bin",
			Length: 4,
			Slices: []SliceChecksum{{MD5: md5.Sum(chunk), CRC32: 0xDEADBEEF}},
		}},
	}
	vr, _ := rs.Verify(map[string][]byte{"a.bin": data})
	if !vr.Files[0].Damaged {
		t.Fatal("expected damaged via CRC mismatch")
	}
}

func TestVerifyIFSCFallback(t *testing.T) {
	data := bytes.Repeat([]byte{3}, 6) // 2 slices, no per-slice checksums
	rs := &RecoverySet{
		SliceSize: 4,
		Files:     []FileSpec{{Name: "a.bin", Length: 6, FullMD5: md5.Sum(data)}},
	}
	// Correct full MD5 -> good.
	vr, _ := rs.Verify(map[string][]byte{"a.bin": data})
	if vr.Files[0].Damaged {
		t.Fatalf("fallback should pass: %+v", vr.Files[0])
	}
	// Wrong content (same length) -> full MD5 mismatch -> all slices damaged.
	bad := bytes.Repeat([]byte{4}, 6)
	vr2, _ := rs.Verify(map[string][]byte{"a.bin": bad})
	if !vr2.Files[0].Damaged || len(vr2.Files[0].MissingSlices) != 2 {
		t.Fatalf("fallback should fail: %+v", vr2.Files[0])
	}
}

func TestVerifyNotRepairable(t *testing.T) {
	files := map[string][]byte{"a.bin": bytes.Repeat([]byte{1}, 8)} // 2 slices
	rs, _ := Create(4, files, 1)                                    // only 1 recovery slice
	bad := bytes.Repeat([]byte{2}, 8)                               // both slices damaged
	vr, _ := rs.Verify(map[string][]byte{"a.bin": bad})
	if vr.Repairable {
		t.Fatal("2 damaged > 1 recovery should be unrepairable")
	}
}

func TestRepairRoundTrip(t *testing.T) {
	a := []byte("The quick brown fox jumps!") // 26 bytes
	b := []byte("0123456789ABCDEF")           // 16 bytes
	orig := map[string][]byte{"a.bin": a, "b.bin": b}
	rs, err := Create(8, orig, 4)
	if err != nil {
		t.Fatal(err)
	}
	// Damage: drop b entirely (2 slices) and corrupt one slice of a.
	dmg := map[string][]byte{"a.bin": append([]byte(nil), a...)}
	dmg["a.bin"][0] ^= 0xFF // corrupts slice 0 of a
	out, err := rs.Repair(dmg)
	if err != nil {
		t.Fatalf("Repair: %v", err)
	}
	if !bytes.Equal(out["a.bin"], a) {
		t.Errorf("a mismatch:\n got %q\nwant %q", out["a.bin"], a)
	}
	if !bytes.Equal(out["b.bin"], b) {
		t.Errorf("b mismatch:\n got %q\nwant %q", out["b.bin"], b)
	}
}

func TestRepairNothingDamaged(t *testing.T) {
	a := []byte("intact content!!")
	orig := map[string][]byte{"a.bin": a}
	rs, _ := Create(4, orig, 1)
	out, err := rs.Repair(orig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out["a.bin"], a) {
		t.Fatalf("got %q", out["a.bin"])
	}
}

func TestRepairOddSliceSize(t *testing.T) {
	// Odd slice size exercises the odd-word handling in bytesToWords.
	a := []byte{1, 2, 3, 4, 5} // 2 slices of size 3
	orig := map[string][]byte{"a.bin": a}
	rs, _ := Create(3, orig, 2)
	dmg := map[string][]byte{} // whole file missing (2 slices) <= 2 recovery
	out, err := rs.Repair(dmg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out["a.bin"], a) {
		t.Fatalf("got %v want %v", out["a.bin"], a)
	}
}

func TestRepairNotRepairable(t *testing.T) {
	files := map[string][]byte{"a.bin": bytes.Repeat([]byte{1}, 8)}
	rs, _ := Create(4, files, 1)
	if _, err := rs.Repair(map[string][]byte{}); !errors.Is(err, ErrNotRepairable) {
		t.Fatalf("err = %v", err)
	}
}

func TestRepairVerifyError(t *testing.T) {
	rs := &RecoverySet{}
	if _, err := rs.Repair(nil); !errors.Is(err, ErrNoSliceSize) {
		t.Fatalf("err = %v", err)
	}
}

func TestRepairSingularMatrix(t *testing.T) {
	// Two recovery slices with identical exponent 0 -> singular system.
	data := bytes.Repeat([]byte{5}, 8) // 2 slices
	rs := &RecoverySet{
		SliceSize: 4,
		Files:     []FileSpec{{Name: "a.bin", Length: 8}}, // no checksums -> fallback
		Recovery: []RecoverySlice{
			{Exponent: 0, Data: []byte{0, 0, 0, 0}},
			{Exponent: 0, Data: []byte{0, 0, 0, 0}},
		},
	}
	// File present but wrong content -> both slices damaged (unknown), u=2.
	if _, err := rs.Repair(map[string][]byte{"a.bin": data}); !errors.Is(err, ErrNotRepairable) {
		t.Fatalf("err = %v, want ErrNotRepairable", err)
	}
}

func TestCreateErrors(t *testing.T) {
	if _, err := Create(0, nil, 1); !errors.Is(err, ErrOddSliceSize) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateNoRecovery(t *testing.T) {
	rs, err := Create(4, map[string][]byte{"a.bin": {1, 2, 3, 4}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Recovery) != 0 || len(rs.Files) != 1 || len(rs.Files[0].Slices) != 1 {
		t.Fatalf("rs = %+v", rs)
	}
	if rs.Creator != "go-newsgroups/par2" {
		t.Errorf("creator = %q", rs.Creator)
	}
}

func TestHelpers(t *testing.T) {
	if numSlices(0, 4) != 0 {
		t.Error("numSlices(0)")
	}
	if numSlices(5, 4) != 2 {
		t.Error("numSlices(5,4)")
	}
	// sliceOf beyond data end -> zero padding.
	if got := sliceOf([]byte{1, 2, 3}, 5, 4); !bytes.Equal(got, make([]byte, 4)) {
		t.Errorf("sliceOf pad = %v", got)
	}
	if sliceWords(3) != 2 || sliceWords(4) != 2 {
		t.Error("sliceWords")
	}
	// bytesToWords: odd trailing byte and short-slice break.
	w := bytesToWords([]byte{1, 2, 3}, 3)
	if w[0] != 0x0102 || w[1] != 0x0300 || w[2] != 0 {
		t.Errorf("bytesToWords = %v", w)
	}
	if !bytes.Equal(wordsToBytes([]uint16{0x0102}), []byte{1, 2}) {
		t.Error("wordsToBytes")
	}
	if coef(0, 0) != 1 {
		t.Error("coef(0,0)")
	}
}

func TestGaussJordan(t *testing.T) {
	// Swap + skip (zero non-pivot) + eliminate, all in one invertible system.
	a := [][]uint16{{0, 1}, {1, 1}}
	b := [][]uint16{{2}, {3}}
	if !gaussJordan(a, b) {
		t.Fatal("expected solvable")
	}
	// Singular system.
	sa := [][]uint16{{1, 1}, {1, 1}}
	sb := [][]uint16{{1}, {1}}
	if gaussJordan(sa, sb) {
		t.Fatal("expected singular")
	}
	// Identity exercises the a[r][p]==0 elimination skip on both pivots.
	ia := [][]uint16{{1, 0}, {0, 1}}
	ib := [][]uint16{{7}, {9}}
	if !gaussJordan(ia, ib) || ib[0][0] != 7 || ib[1][0] != 9 {
		t.Fatalf("identity solve = %v", ib)
	}
}
