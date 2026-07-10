// Package par2 implements a pure-Go (CGO-free) parser, verifier and repairer
// for PAR2 recovery sets — the format behind the "AutoPAR" feature used to
// protect Usenet binaries.
//
// The package can:
//
//   - Parse concatenated .par2 blobs into a [RecoverySet], validating every
//     packet's MD5 and skipping unknown or corrupt packets.
//   - Verify supplied file contents against the recovery set using the
//     per-slice MD5+CRC32 checksums from the Input File Slice Checksum packets
//     (hash based, independent of Reed-Solomon).
//   - Repair missing or damaged input slices from the available recovery
//     slices via Reed-Solomon over GF(2^16).
//   - Create recovery slices for a set of input files (a minimal generator
//     side, enough for AutoPAR self-consistency and round-trip testing).
//
// # Compatibility caveat
//
// Verify is hash based and is correct against real PAR2 files. Repair and
// Create implement the Vandermonde Reed-Solomon scheme described in the PAR2
// specification on top of the go-erasure/reedsolomon GF(2^16) field, and are
// validated here by self-consistent round-trip (Create → damage → Repair →
// bytes match). Byte-exact interoperability with recovery data produced by
// par2cmdline or QuickPar is NOT yet validated against those tools and is a
// planned follow-up (real-oracle validation).
package par2

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// magic is the 8-byte signature at the start of every PAR2 packet.
var magic = []byte("PAR2\x00PKT")

// Packet type identifiers (16 bytes, space/NUL padded as defined by PAR2).
var (
	typeMain     = []byte("PAR 2.0\x00Main\x00\x00\x00\x00")
	typeFileDesc = []byte("PAR 2.0\x00FileDesc")
	typeIFSC     = []byte("PAR 2.0\x00IFSC\x00\x00\x00\x00")
	typeRecvSlic = []byte("PAR 2.0\x00RecvSlic")
	typeCreator  = []byte("PAR 2.0\x00Creator\x00")
)

const headerLen = 64

// Errors returned by the package.
var (
	// ErrNoMainPacket is returned by Parse when no valid Main packet is found.
	ErrNoMainPacket = errors.New("par2: no main packet found")
	// ErrMissingFileDesc is returned by Parse when the Main packet references a
	// recovery-set file that has no File Description packet.
	ErrMissingFileDesc = errors.New("par2: missing file description packet")
	// ErrNoSliceSize is returned when the slice size is zero.
	ErrNoSliceSize = errors.New("par2: slice size is zero")
	// ErrNotRepairable is returned by Repair when there are more damaged input
	// slices than available recovery slices, or the recovery matrix is singular.
	ErrNotRepairable = errors.New("par2: not enough recovery slices to repair")
	// ErrOddSliceSize is returned by Create for a zero slice size.
	ErrOddSliceSize = errors.New("par2: slice size must be non-zero")
)

// SliceChecksum is the MD5 and CRC32 of a single input slice.
type SliceChecksum struct {
	MD5   [16]byte
	CRC32 uint32
}

// FileSpec describes one recovery-set input file.
type FileSpec struct {
	ID      [16]byte
	Name    string
	Length  uint64
	FullMD5 [16]byte
	Slices  []SliceChecksum // from the IFSC packet (may be empty if absent)
}

// RecoverySlice is one recovery slice (an exponent plus its data).
type RecoverySlice struct {
	Exponent uint32
	Data     []byte
}

// RecoverySet is a parsed PAR2 recovery set.
type RecoverySet struct {
	SliceSize uint64
	Files     []FileSpec      // recovery-set files, in Main-packet order
	Recovery  []RecoverySlice // available recovery slices
	Creator   string
}

// fileDesc is the intermediate parse result for a File Description packet.
type fileDesc struct {
	name    string
	length  uint64
	fullMD5 [16]byte
}

// Parse reads all PAR2 packets from one or more concatenated .par2 blobs and
// assembles a RecoverySet. Packets with a bad header MD5, an unknown type, or a
// truncated/malformed body are skipped; a valid Main packet is required.
func Parse(blobs ...[]byte) (*RecoverySet, error) {
	var (
		haveMain    bool
		sliceSize   uint64
		order       [][16]byte
		descs       = map[[16]byte]fileDesc{}
		ifsc        = map[[16]byte][]SliceChecksum{}
		recovery    []RecoverySlice
		creator     string
		haveCreator bool
	)

	for _, blob := range blobs {
		pos := 0
		for {
			idx := bytes.Index(blob[pos:], magic)
			if idx < 0 {
				break
			}
			off := pos + idx
			// Need at least a full header.
			if off+headerLen > len(blob) {
				break
			}
			length := binary.LittleEndian.Uint64(blob[off+8 : off+16])
			if length < headerLen || length%4 != 0 || uint64(off)+length > uint64(len(blob)) {
				// Truncated or malformed packet: resume scanning past the magic.
				pos = off + len(magic)
				continue
			}
			end := off + int(length)
			wantMD5 := blob[off+16 : off+32]
			got := md5.Sum(blob[off+32 : end])
			if !bytes.Equal(wantMD5, got[:]) {
				pos = end
				continue
			}
			ptype := blob[off+48 : off+64]
			body := blob[off+64 : end]

			switch {
			case bytes.Equal(ptype, typeMain):
				if ss, ord, ok := parseMain(body); ok && !haveMain {
					haveMain = true
					sliceSize = ss
					order = ord
				}
			case bytes.Equal(ptype, typeFileDesc):
				if id, d, ok := parseFileDesc(body); ok {
					if _, dup := descs[id]; !dup {
						descs[id] = d
					}
				}
			case bytes.Equal(ptype, typeIFSC):
				if id, sums, ok := parseIFSC(body); ok {
					if _, dup := ifsc[id]; !dup {
						ifsc[id] = sums
					}
				}
			case bytes.Equal(ptype, typeRecvSlic):
				if rsl, ok := parseRecvSlic(body); ok {
					recovery = append(recovery, rsl)
				}
			case bytes.Equal(ptype, typeCreator):
				if !haveCreator {
					creator = string(bytes.TrimRight(body, "\x00 "))
					haveCreator = true
				}
			default:
				// Unknown packet type: ignore.
			}
			pos = end
		}
	}

	if !haveMain {
		return nil, ErrNoMainPacket
	}

	rs := &RecoverySet{
		SliceSize: sliceSize,
		Recovery:  recovery,
		Creator:   creator,
	}
	for _, id := range order {
		d, ok := descs[id]
		if !ok {
			return nil, ErrMissingFileDesc
		}
		rs.Files = append(rs.Files, FileSpec{
			ID:      id,
			Name:    d.name,
			Length:  d.length,
			FullMD5: d.fullMD5,
			Slices:  ifsc[id],
		})
	}
	return rs, nil
}

// parseMain parses a Main packet body, returning the slice size and the ordered
// list of recovery-set file IDs.
func parseMain(body []byte) (sliceSize uint64, order [][16]byte, ok bool) {
	if len(body) < 12 {
		return 0, nil, false
	}
	sliceSize = binary.LittleEndian.Uint64(body[0:8])
	count := binary.LittleEndian.Uint32(body[8:12])
	need := 12 + int(count)*16
	if need > len(body) {
		return 0, nil, false
	}
	order = make([][16]byte, 0, count)
	for i := 0; i < int(count); i++ {
		var id [16]byte
		copy(id[:], body[12+i*16:12+i*16+16])
		order = append(order, id)
	}
	return sliceSize, order, true
}

// parseFileDesc parses a File Description packet body.
func parseFileDesc(body []byte) (id [16]byte, d fileDesc, ok bool) {
	if len(body) < 56 {
		return id, d, false
	}
	copy(id[:], body[0:16])
	copy(d.fullMD5[:], body[16:32])
	d.length = binary.LittleEndian.Uint64(body[48:56])
	d.name = string(bytes.TrimRight(body[56:], "\x00 "))
	return id, d, true
}

// parseIFSC parses an Input File Slice Checksum packet body.
func parseIFSC(body []byte) (id [16]byte, sums []SliceChecksum, ok bool) {
	if len(body) < 16 || (len(body)-16)%20 != 0 {
		return id, nil, false
	}
	copy(id[:], body[0:16])
	n := (len(body) - 16) / 20
	sums = make([]SliceChecksum, 0, n)
	for i := 0; i < n; i++ {
		base := 16 + i*20
		var sc SliceChecksum
		copy(sc.MD5[:], body[base:base+16])
		sc.CRC32 = binary.LittleEndian.Uint32(body[base+16 : base+20])
		sums = append(sums, sc)
	}
	return id, sums, true
}

// parseRecvSlic parses a Recovery Slice packet body.
func parseRecvSlic(body []byte) (rsl RecoverySlice, ok bool) {
	if len(body) < 4 {
		return rsl, false
	}
	rsl.Exponent = binary.LittleEndian.Uint32(body[0:4])
	rsl.Data = append([]byte(nil), body[4:]...)
	return rsl, true
}

// crc32IEEE returns the PAR2 (IEEE) CRC32 of b.
func crc32IEEE(b []byte) uint32 { return crc32.ChecksumIEEE(b) }
