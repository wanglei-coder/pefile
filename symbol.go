package pe

import (
	"encoding/binary"
	"io"

	"github.com/pkg/errors"
)

const COFFSymbolSize = 18

// COFFSymbol represents single COFF symbol table record.
type COFFSymbol struct {
	Name               [8]uint8
	Value              uint32
	SectionNumber      int16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

func (f *File) readCOFFSymbols() error {
	if f.FileHeader.PointerToSymbolTable == 0 {
		return nil
	}
	if f.FileHeader.NumberOfSymbols <= 0 {
		return nil
	}
	_, err := f.sr.Seek(int64(f.FileHeader.PointerToSymbolTable), io.SeekStart)
	if err != nil {
		return errors.WithMessage(err, "fail to seek to symbol table")
	}
	symbols := make([]COFFSymbol, f.FileHeader.NumberOfSymbols)
	err = binary.Read(f.sr, binary.LittleEndian, symbols)
	if err != nil {
		return errors.WithMessage(err, "fail to read to symbol table")
	}

	f.COFFSymbols = symbols
	return nil
}

// isSymNameOffset checks symbol name if it is encoded as offset into string table.
func isSymNameOffset(name [8]byte) (bool, uint32) {
	if name[0] == 0 && name[1] == 0 && name[2] == 0 && name[3] == 0 {
		return true, binary.LittleEndian.Uint32(name[4:])
	}
	return false, 0
}

// FullName finds real name of symbol sym. Normally name is stored
// in sym.Name, but if it is longer then 8 characters, it is stored
// in COFF string table st instead.
func (sym *COFFSymbol) FullName(st StringTable) (string, error) {
	if ok, offset := isSymNameOffset(sym.Name); ok {
		return st.String(offset)
	}
	return cString(sym.Name[:]), nil
}

func (f *File) removeAuxSymbols(allSymbols []COFFSymbol, st StringTable) error {
	if len(allSymbols) == 0 {
		return nil
	}
	symbols := make([]*Symbol, 0)
	aux := uint8(0)
	for _, sym := range allSymbols {
		if aux > 0 {
			aux--
			continue
		}
		name, err := sym.FullName(st)
		if err != nil {
			return err
		}
		aux = sym.NumberOfAuxSymbols
		s := &Symbol{
			Name:          name,
			Value:         sym.Value,
			SectionNumber: sym.SectionNumber,
			Type:          sym.Type,
			StorageClass:  sym.StorageClass,
		}
		symbols = append(symbols, s)
	}
	f.Symbols = symbols
	return nil
}

// Symbol is similar to COFFSymbol with Name field replaced
// by Go string. Symbol also does not have NumberOfAuxSymbols.
type Symbol struct {
	Name          string
	Value         uint32
	SectionNumber int16
	Type          uint16
	StorageClass  uint8
}
