package par2

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"testing"
)

// pkt assembles a full PAR2 packet (header + body) with a correct MD5. The body
// is zero-padded to a multiple of 4 as required by the format.
func pkt(setID [16]byte, ptype, body []byte) []byte {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	length := headerLen + len(body)
	buf := make([]byte, length)
	copy(buf[0:8], magic)
	binary.LittleEndian.PutUint64(buf[8:16], uint64(length))
	copy(buf[32:48], setID[:])
	copy(buf[48:64], ptype)
	copy(buf[64:], body)
	sum := md5.Sum(buf[32:])
	copy(buf[16:32], sum[:])
	return buf
}

func mainBody(sliceSize uint64, ids ...[16]byte) []byte {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint64(b[0:8], sliceSize)
	binary.LittleEndian.PutUint32(b[8:12], uint32(len(ids)))
	for _, id := range ids {
		b = append(b, id[:]...)
	}
	return b
}

func fileDescBody(id [16]byte, name string, length uint64) []byte {
	b := make([]byte, 56)
	copy(b[0:16], id[:])
	// fullMD5 (16), md5-16k (16) left as recognisable bytes
	for i := 16; i < 48; i++ {
		b[i] = byte(i)
	}
	binary.LittleEndian.PutUint64(b[48:56], length)
	b = append(b, name...)
	return b
}

func ifscBody(id [16]byte, n int) []byte {
	b := make([]byte, 16)
	copy(b[0:16], id[:])
	for i := 0; i < n; i++ {
		entry := make([]byte, 20)
		entry[0] = byte(i + 1)
		binary.LittleEndian.PutUint32(entry[16:20], uint32(i+100))
		b = append(b, entry...)
	}
	return b
}

func recvBody(exp uint32, data []byte) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b[0:4], exp)
	return append(b, data...)
}

func TestParseHappy(t *testing.T) {
	set := [16]byte{1, 2, 3}
	id1 := [16]byte{'a'}
	id2 := [16]byte{'b'}

	var blob []byte
	blob = append(blob, pkt(set, typeMain, mainBody(4, id1, id2))...)
	blob = append(blob, pkt(set, typeFileDesc, fileDescBody(id1, "a.bin", 10))...)
	blob = append(blob, pkt(set, typeFileDesc, fileDescBody(id2, "b.bin", 4))...)
	blob = append(blob, pkt(set, typeIFSC, ifscBody(id1, 3))...)
	blob = append(blob, pkt(set, typeIFSC, ifscBody(id2, 1))...)
	blob = append(blob, pkt(set, typeRecvSlic, recvBody(0, []byte{1, 2, 3, 4}))...)
	blob = append(blob, pkt(set, typeRecvSlic, recvBody(1, []byte{5, 6, 7, 8}))...)
	blob = append(blob, pkt(set, typeCreator, []byte("test\x00"))...)
	// Unknown packet type (must be ignored).
	blob = append(blob, pkt(set, []byte("PAR 2.0\x00Unknown\x00"), []byte("junk"))...)
	// Duplicate main / filedesc / creator / ifsc (must be ignored).
	blob = append(blob, pkt(set, typeMain, mainBody(999, id1))...)
	blob = append(blob, pkt(set, typeFileDesc, fileDescBody(id1, "other", 99))...)
	blob = append(blob, pkt(set, typeIFSC, ifscBody(id1, 1))...)
	blob = append(blob, pkt(set, typeCreator, []byte("second"))...)
	// A packet with a corrupt MD5 (must be skipped).
	bad := pkt(set, typeRecvSlic, recvBody(9, []byte{0, 0, 0, 0}))
	bad[16] ^= 0xFF
	blob = append(blob, bad...)

	rs, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if rs.SliceSize != 4 {
		t.Fatalf("SliceSize = %d, want 4", rs.SliceSize)
	}
	if len(rs.Files) != 2 {
		t.Fatalf("Files = %d, want 2", len(rs.Files))
	}
	if rs.Files[0].Name != "a.bin" || rs.Files[0].Length != 10 || len(rs.Files[0].Slices) != 3 {
		t.Errorf("file0 = %+v", rs.Files[0])
	}
	if rs.Files[1].Name != "b.bin" || len(rs.Files[1].Slices) != 1 {
		t.Errorf("file1 = %+v", rs.Files[1])
	}
	if len(rs.Recovery) != 2 {
		t.Errorf("Recovery = %d, want 2", len(rs.Recovery))
	}
	if rs.Recovery[0].Exponent != 0 || !bytes.Equal(rs.Recovery[0].Data, []byte{1, 2, 3, 4}) {
		t.Errorf("recovery0 = %+v", rs.Recovery[0])
	}
	if rs.Creator != "test" {
		t.Errorf("Creator = %q, want test", rs.Creator)
	}
}

func TestParseNoMagic(t *testing.T) {
	if _, err := Parse([]byte("no par2 data here")); !errors.Is(err, ErrNoMainPacket) {
		t.Fatalf("err = %v, want ErrNoMainPacket", err)
	}
}

func TestParseTruncatedHeader(t *testing.T) {
	blob := append([]byte(nil), magic...)
	blob = append(blob, 0, 0, 0, 0) // header cut short
	if _, err := Parse(blob); !errors.Is(err, ErrNoMainPacket) {
		t.Fatalf("err = %v, want ErrNoMainPacket", err)
	}
}

func TestParseBadLengthFields(t *testing.T) {
	set := [16]byte{7}
	base := pkt(set, typeMain, mainBody(4))

	// length < headerLen
	b1 := append([]byte(nil), base...)
	binary.LittleEndian.PutUint64(b1[8:16], 0)
	// length not multiple of 4
	b2 := append([]byte(nil), base...)
	binary.LittleEndian.PutUint64(b2[8:16], 65)
	// length beyond end of blob
	b3 := append([]byte(nil), base...)
	binary.LittleEndian.PutUint64(b3[8:16], uint64(len(b3)+4))

	for name, b := range map[string][]byte{"short": b1, "unaligned": b2, "overrun": b3} {
		if _, err := Parse(b); !errors.Is(err, ErrNoMainPacket) {
			t.Errorf("%s: err = %v, want ErrNoMainPacket", name, err)
		}
	}
}

func TestParseMissingFileDesc(t *testing.T) {
	set := [16]byte{3}
	id := [16]byte{'x'}
	blob := pkt(set, typeMain, mainBody(4, id))
	if _, err := Parse(blob); !errors.Is(err, ErrMissingFileDesc) {
		t.Fatalf("err = %v, want ErrMissingFileDesc", err)
	}
}

func TestParseMalformedBodies(t *testing.T) {
	set := [16]byte{5}
	// Count-0 main as scaffold; malformed sub-packets must be skipped, leaving a
	// valid (empty) recovery set.
	var blob []byte
	blob = append(blob, pkt(set, typeMain, mainBody(4))...)
	blob = append(blob, pkt(set, typeFileDesc, []byte("short"))...)            // <56
	blob = append(blob, pkt(set, typeIFSC, []byte("0123456789abcdef"))...)     // len 16 -> first clause
	blob = append(blob, pkt(set, typeIFSC, []byte("0123456789abcdefEXTR"))...) // 20 -> misaligned
	blob = append(blob, pkt(set, typeRecvSlic, nil)...)                        // <4
	rs, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rs.Files) != 0 || len(rs.Recovery) != 0 {
		t.Fatalf("expected empty set, got %+v", rs)
	}
}

func TestParseMainTooShortAndCountOverrun(t *testing.T) {
	set := [16]byte{6}
	// Main body under 12 bytes.
	if _, err := Parse(pkt(set, typeMain, []byte{1, 2, 3, 4})); !errors.Is(err, ErrNoMainPacket) {
		t.Errorf("short main: err = %v", err)
	}
	// Main claims 5 files but supplies one ID.
	body := mainBody(4, [16]byte{1})
	binary.LittleEndian.PutUint32(body[8:12], 5)
	if _, err := Parse(pkt(set, typeMain, body)); !errors.Is(err, ErrNoMainPacket) {
		t.Errorf("overrun main: err = %v", err)
	}
}

func TestParseMultipleBlobs(t *testing.T) {
	set := [16]byte{2}
	id := [16]byte{'a'}
	main := pkt(set, typeMain, mainBody(4, id))
	desc := pkt(set, typeFileDesc, fileDescBody(id, "a.bin", 4))
	rs, err := Parse(main, desc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rs.Files) != 1 || rs.Files[0].Name != "a.bin" {
		t.Fatalf("files = %+v", rs.Files)
	}
}
