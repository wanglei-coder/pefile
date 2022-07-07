package pe

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
)

type RichHeader struct {
	XorKey     uint32
	CompIDs    []CompID
	DansOffset int
	Raw        []byte
}

type CompID struct {
	MinorCV  uint16
	ProdID   uint16
	Count    uint32
	Unmasked uint32
}

func (f *File) readRichHeader() (err error) {

	var rh RichHeader
	richData, err := f.GetData(0, f.AddressOfNewEXEHeader)
	if err != nil {
		return err
	}
	richSigOffset := bytes.Index(richData, []byte(RichSignature))

	if richSigOffset < 0 {
		return nil
	}

	if rh.XorKey, err = f.ReadUint32(uint32(richSigOffset + 4)); err != nil {
		return err
	}

	var decRichHeader []uint32
	dansSigOffset := -1
	estimatedBeginDans := richSigOffset - 4 - binary.Size(DOSHeader{})
	for it := 0; it < estimatedBeginDans; it += 4 {
		buff, err := f.ReadUint32(uint32(richSigOffset - 4 - it))
		if err != nil {
			return err
		}

		res := buff ^ rh.XorKey
		if res == DansSignature {
			dansSigOffset = richSigOffset - it - 4
			break
		}
		decRichHeader = append(decRichHeader, res)
	}

	if dansSigOffset == -1 {
		return nil
	}

	rh.DansOffset = dansSigOffset
	rh.Raw, err = f.GetData(uint32(dansSigOffset), uint32(richSigOffset+8-dansSigOffset))
	if err != nil {
		return err
	}

	for i, j := 0, len(decRichHeader)-1; i < j; i, j = i+1, j-1 {
		decRichHeader[i], decRichHeader[j] = decRichHeader[j], decRichHeader[i]
	}

	lenCompIDs := len(decRichHeader)
	if (len(decRichHeader)-3)%2 != 0 {
		lenCompIDs = len(decRichHeader) - 1
	}

	for i := 3; i < lenCompIDs; i += 2 {
		var cid CompID
		compId := make([]byte, binary.Size(cid))
		binary.LittleEndian.PutUint32(compId, decRichHeader[i])
		binary.LittleEndian.PutUint32(compId[4:], decRichHeader[i+1])
		if err := binary.Read(bytes.NewReader(compId), binary.LittleEndian, &cid); err != nil {
			break
		}
		cid.Unmasked = binary.LittleEndian.Uint32(compId)
		rh.CompIDs = append(rh.CompIDs, cid)
	}

	f.RichHeader = &rh
	return nil
}

func (f *File) RichHeaderChecksum() uint32 {
	if f.RichHeader == nil {
		return 0
	}

	checksum := uint32(f.RichHeader.DansOffset)

	// First, calculate the sum of the DOS header bytes each rotated left the
	// number of times their position relative to the start of the DOS header e.g.
	// second byte is rotated left 2x using rol operation.
	for i := 0; i < f.RichHeader.DansOffset; i++ {
		// skip over dos e_lfanew field at offset 0x3C
		if i >= 0x3C && i < 0x40 {
			continue
		}
		_b, err := f.GetByte(i)
		if err != nil {
			return 0
		}
		b := uint32(_b)
		checksum += (b << (i % 32)) | (b>>(32-(i%32)))&0xff
		checksum &= 0xFFFFFFFF
	}

	// Next, take summation of each Rich header entry by combining its ProductId
	// and BuildNumber into a single 32 bits number and rotating by its count.
	for _, compID := range f.RichHeader.CompIDs {
		checksum += compID.Unmasked<<(compID.Count%32) | compID.Unmasked>>(32-(compID.Count%32))
		checksum &= 0xFFFFFFFF
	}

	return checksum
}

func (f *File) RichHeaderHash() string {
	if f.RichHeader == nil {
		return ""
	}
	richIndex := bytes.Index(f.RichHeader.Raw, []byte(RichSignature))
	if richIndex == -1 {
		return ""
	}

	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, f.RichHeader.XorKey)

	rawData := f.RichHeader.Raw[:richIndex]
	clearData := make([]byte, len(rawData))
	for idx, val := range rawData {
		clearData[idx] = val ^ key[idx%len(key)]
	}
	return fmt.Sprintf("%x", md5.Sum(clearData))
}
