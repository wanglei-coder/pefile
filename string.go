package pe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pkg/errors"
)

type COFF struct {
	SymbolTable       []COFFSymbol
	StringTable       []string
	StringTableOffset uint32
	StringTableM      map[uint32]string
}

// cString converts ASCII byte sequence b to string.
// It stops once it finds 0 or reaches end of b.
func cString(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		i = len(b)
	}
	return string(b[:i])
}

// StringTable is a COFF string table.
type StringTable []byte

func (f *File) readStringTable() error {
	// COFF string table is located right after COFF symbol table.
	if f.FileHeader.PointerToSymbolTable <= 0 {
		return nil
	}
	offset := f.FileHeader.PointerToSymbolTable + COFFSymbolSize*f.FileHeader.NumberOfSymbols
	_, err := f.sr.Seek(int64(offset), io.SeekStart)
	if err != nil {
		return fmt.Errorf("fail to seek to string table: %v", err)
	}
	var l uint32
	err = binary.Read(f.sr, binary.LittleEndian, &l)
	if err != nil {
		return errors.WithMessage(err, "fail to read string table length")
	}
	// string table length includes itself
	if l <= 4 {
		return nil
	}
	l -= 4
	buf := make([]byte, l)
	_, err = io.ReadFull(f.sr, buf)
	if err != nil {
		return fmt.Errorf("fail to read string table: %v", err)
	}
	f.StringTable = buf
	return nil
}

// String extracts string from COFF string table st at offset start.
func (st StringTable) String(start uint32) (string, error) {
	// start includes 4 bytes of string table length
	if start < 4 {
		return "", fmt.Errorf("offset %d is before the start of string table", start)
	}
	start -= 4
	if int(start) > len(st) {
		return "", fmt.Errorf("offset %d is beyond the end of string table", start)
	}
	return cString(st[start:]), nil
}
