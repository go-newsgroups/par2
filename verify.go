package par2

import "crypto/md5"

// VerifyResult reports the state of the target files against the recovery set.
type VerifyResult struct {
	Complete   bool // every file fully present & correct
	Files      []FileStatus
	Repairable bool // missing/damaged slices <= available recovery slices
}

// FileStatus is the per-file result of a Verify.
type FileStatus struct {
	Name          string
	Present       bool  // file supplied at all
	Damaged       bool  // some slices fail checksum
	MissingSlices []int // slice indices that are missing/damaged (global slice numbering)
}

// numSlices returns the number of slices a file of the given length occupies.
func numSlices(length, sliceSize uint64) int {
	if length == 0 {
		return 0
	}
	return int((length + sliceSize - 1) / sliceSize)
}

// sliceOf returns slice s of data, zero-padded to sliceSize bytes.
func sliceOf(data []byte, s int, sliceSize uint64) []byte {
	out := make([]byte, sliceSize)
	start := uint64(s) * sliceSize
	if start >= uint64(len(data)) {
		return out
	}
	copy(out, data[start:])
	return out
}

// Verify checks the supplied file contents against the recovery set using the
// IFSC MD5+CRC32 per slice and the file length. It is hash based and
// independent of Reed-Solomon.
func (rs *RecoverySet) Verify(files map[string][]byte) (*VerifyResult, error) {
	if rs.SliceSize == 0 {
		return nil, ErrNoSliceSize
	}
	res := &VerifyResult{Complete: true}
	global := 0
	totalMissing := 0

	for _, f := range rs.Files {
		n := numSlices(f.Length, rs.SliceSize)
		base := global
		global += n

		fs := FileStatus{Name: f.Name}
		data, present := files[f.Name]
		fs.Present = present

		if !present {
			// Every slice of a missing file is missing.
			for s := 0; s < n; s++ {
				fs.MissingSlices = append(fs.MissingSlices, base+s)
			}
			totalMissing += n
			res.Complete = false
			res.Files = append(res.Files, fs)
			continue
		}

		lengthOK := uint64(len(data)) == f.Length
		damaged := !lengthOK

		for s := 0; s < n; s++ {
			if lengthOK && sliceGood(f, s, data, rs.SliceSize) {
				continue
			}
			damaged = true
			fs.MissingSlices = append(fs.MissingSlices, base+s)
			totalMissing++
		}
		fs.Damaged = damaged
		if damaged {
			res.Complete = false
		}
		res.Files = append(res.Files, fs)
	}

	res.Repairable = totalMissing <= len(rs.Recovery)
	return res, nil
}

// sliceGood reports whether slice s of data matches file f's recorded checksum.
// When the file has no per-slice checksums (IFSC absent), it falls back to
// comparing the full-file MD5.
func sliceGood(f FileSpec, s int, data []byte, sliceSize uint64) bool {
	if s < len(f.Slices) {
		chunk := sliceOf(data, s, sliceSize)
		sum := md5.Sum(chunk)
		if sum != f.Slices[s].MD5 {
			return false
		}
		return crc32IEEE(chunk) == f.Slices[s].CRC32
	}
	// No per-slice checksum available: fall back to full-file MD5.
	return md5.Sum(data) == f.FullMD5
}
