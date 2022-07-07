package pe

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type ImageImportDirectory struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

type ImageThunkData32 struct {
	AddressOfData uint32
}

type ImageThunkData64 struct {
	AddressOfData uint64
}

type ThunkData32 struct {
	ImageThunkData ImageThunkData32
	Offset         uint32
}

type ThunkData64 struct {
	ImageThunkData ImageThunkData64
	Offset         uint32
}

type ImportFunction struct {
	Name               string
	Hint               uint16
	ByOrdinal          bool
	Ordinal            uint32
	OriginalThunkValue uint64
	ThunkValue         uint64
	ThunkRVA           uint32
	OriginalThunkRVA   uint32
}

type Import struct {
	Offset     uint32
	Name       string
	Functions  []*ImportFunction
	Descriptor ImageImportDirectory
}

func (f *File) readImportDirectory() (err error) {
	if f.OptionalHeader == nil {
		return nil
	}

	var ddLength uint32
	if f.Is64 {
		ddLength = f.OptionalHeader.(*OptionalHeader64).NumberOfRvaAndSizes
	} else {
		ddLength = f.OptionalHeader.(*OptionalHeader32).NumberOfRvaAndSizes
	}

	if ddLength < ImageDirectoryEntryImport+1 {
		return nil
	}

	// grab the import data directory entry
	var idd DataDirectory
	if f.Is64 {
		idd = f.OptionalHeader.(*OptionalHeader64).DataDirectory[ImageDirectoryEntryImport]
	} else {
		idd = f.OptionalHeader.(*OptionalHeader32).DataDirectory[ImageDirectoryEntryImport]
	}

	// figure out which section contains the import directory table
	var ds *Section
	ds = nil
	for _, s := range f.Sections {
		if s.VirtualAddress <= idd.VirtualAddress && idd.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			ds = s
			break
		}
	}

	if ds == nil {
		return nil
	}

	d, err := ds.Data()
	if err != nil {
		return err
	}
	d = d[idd.VirtualAddress-ds.VirtualAddress:]
	var ida []ImageImportDirectory
	for len(d) >= 20 {
		var dt ImageImportDirectory
		dt.OriginalFirstThunk = binary.LittleEndian.Uint32(d[0:4])
		dt.TimeDateStamp = binary.LittleEndian.Uint32(d[4:8])
		dt.ForwarderChain = binary.LittleEndian.Uint32(d[8:12])
		dt.Name = binary.LittleEndian.Uint32(d[12:16])
		dt.FirstThunk = binary.LittleEndian.Uint32(d[16:20])
		d = d[20:]
		if dt.OriginalFirstThunk == 0 {
			break
		}
		ida = append(ida, dt)
	}

	var rva = idd.VirtualAddress
	var importDescSize = uint32(binary.Size(ImageImportDirectory{}))

	for _, dt := range ida {
		fileOffset := f.getOffsetFromRva(rva)
		rva += importDescSize

		maxLen := f.size - fileOffset
		if rva > dt.OriginalFirstThunk || rva > dt.FirstThunk {
			switch {
			case rva < dt.OriginalFirstThunk:
				maxLen = rva - dt.FirstThunk
			case rva < dt.FirstThunk:
				maxLen = rva - dt.OriginalFirstThunk
			default:
				maxLen = Max(rva-dt.OriginalFirstThunk, rva-dt.FirstThunk)
			}
		}

		var importedFunctions []*ImportFunction
		if f.Is64 {
			importedFunctions, err = f.readImports64(&dt, maxLen)
		} else {
			importedFunctions, err = f.readImports32(&dt, maxLen)
		}
		if err != nil {
			return err
		}

		dllName := f.getStringAtRVA(dt.Name, maxDllLength)
		if !IsValidDosFilename(dllName) {
			dllName = "*invalid*"
			continue
		}

		f.Imports = append(f.Imports, &Import{
			Offset:     fileOffset,
			Name:       dllName,
			Functions:  importedFunctions,
			Descriptor: dt,
		})
	}
	return nil
}

func (f *File) getImportTable32(rva uint32, maxLen uint32, isOldDelayImport bool) ([]*ThunkData32, error) {
	if f.OptionalHeader == nil {
		return nil, nil
	}
	// Setup variables
	thunkTable := make(map[uint32]*ImageThunkData32)
	retVal := make([]*ThunkData32, 0)
	minAddressOfData := ^uint32(0)
	maxAddressOfData := uint32(0)
	repeatedAddress := uint32(0)
	var size uint32 = 4
	addressesOfData := make(map[uint32]bool)

	startRVA := rva

	if rva == 0 {
		return nil, nil
	}

	for {
		if rva >= startRVA+maxLen {
			break
		}

		offset := uint32(0)
		if isOldDelayImport {
			oh32 := f.NtHeader.OptionalHeader.(*OptionalHeader32)
			newRVA := rva - oh32.ImageBase
			offset = f.getOffsetFromRva(newRVA)
			if offset == ^uint32(0) {
				return nil, nil
			}
		} else {
			offset = f.getOffsetFromRva(rva)
			if offset == ^uint32(0) {
				return nil, nil
			}
		}

		// Read the image thunk data.
		thunk := ImageThunkData32{}
		if err := f.structUnpack(&thunk, offset, size); err != nil {
			return nil, nil
		}

		if thunk == (ImageThunkData32{}) {
			break
		}

		if thunk.AddressOfData >= startRVA && thunk.AddressOfData <= rva {
			break
		}

		if thunk.AddressOfData&imageOrdinalFlag32 > 0 {
			// If the entry looks like could be an ordinal.
			// if thunk.AddressOfData&0x7fffffff > 0xffff {

			// }
		} else {
			// and if it looks like it should be an RVA keep track of the RVAs seen
			// and store them to study their  properties. When certain non-standard
			// features are detected the parsing will be aborted
			_, ok := addressesOfData[thunk.AddressOfData]
			if ok {
				repeatedAddress++
			} else {
				addressesOfData[thunk.AddressOfData] = true
			}

			if thunk.AddressOfData > maxAddressOfData {
				maxAddressOfData = thunk.AddressOfData
			}

			if thunk.AddressOfData < minAddressOfData {
				minAddressOfData = thunk.AddressOfData
			}
		}

		thunkTable[rva] = &thunk
		thunkData := ThunkData32{ImageThunkData: thunk, Offset: rva}
		retVal = append(retVal, &thunkData)
		rva += size
	}
	return retVal, nil
}

func (f *File) getImportTable64(rva uint32, maxLen uint32, isOldDelayImport bool) ([]*ThunkData64, error) {
	if f.OptionalHeader == nil {
		return nil, nil
	}
	// Setup variables
	thunkTable := make(map[uint32]*ImageThunkData64)
	retVal := make([]*ThunkData64, 0)
	minAddressOfData := ^uint64(0)
	maxAddressOfData := uint64(0)
	repeatedAddress := uint64(0)
	var size uint32 = 8
	addressesOfData := make(map[uint64]bool)

	startRVA := rva

	if rva == 0 {
		return nil, nil
	}

	for {
		if rva >= startRVA+maxLen {
			break
		}

		offset := uint32(0)
		if isOldDelayImport {
			oh64 := f.NtHeader.OptionalHeader.(*OptionalHeader64)
			newRVA := rva - uint32(oh64.ImageBase)
			offset = f.getOffsetFromRva(newRVA)
			if offset == ^uint32(0) {
				return nil, nil
			}
		} else {
			offset = f.getOffsetFromRva(rva)
			if offset == ^uint32(0) {
				return nil, nil
			}
		}

		// Read the image thunk data.
		var thunk ImageThunkData64
		err := f.structUnpack(&thunk, offset, size)
		if err != nil {
			return nil, nil
		}

		if thunk == (ImageThunkData64{}) {
			break
		}

		if thunk.AddressOfData >= uint64(startRVA) && thunk.AddressOfData <= uint64(rva) {
			break
		}

		if thunk.AddressOfData&imageOrdinalFlag64 > 0 {
			// if thunk.AddressOfData&0x7fffffff > 0xffff {
			// }
		} else {
			_, ok := addressesOfData[thunk.AddressOfData]
			if ok {
				repeatedAddress++
			} else {
				addressesOfData[thunk.AddressOfData] = true
			}

			if thunk.AddressOfData > maxAddressOfData {
				maxAddressOfData = thunk.AddressOfData
			}

			if thunk.AddressOfData < minAddressOfData {
				minAddressOfData = thunk.AddressOfData
			}
		}

		thunkTable[rva] = &thunk
		thunkData := ThunkData64{ImageThunkData: thunk, Offset: rva}
		retVal = append(retVal, &thunkData)
		rva += size
	}
	return retVal, nil
}

func (f *File) readImports32(dt interface{}, maxLen uint32) ([]*ImportFunction, error) {
	if f.OptionalHeader == nil {
		return nil, nil
	}

	var (
		OriginalFirstThunk uint32
		FirstThunk         uint32
		isOldDelayImport   bool
	)

	switch desc := dt.(type) {
	case *ImageImportDirectory:
		OriginalFirstThunk = desc.OriginalFirstThunk
		FirstThunk = desc.FirstThunk
	case *ImageDelayImportDirectory:
		OriginalFirstThunk = desc.ImportNameTableRVA
		FirstThunk = desc.ImportAddressTableRVA
		if desc.Attributes == 0 {
			isOldDelayImport = true
		}
	}

	ilt, err := f.getImportTable32(OriginalFirstThunk, maxLen, isOldDelayImport)
	if err != nil {
		return nil, err
	}

	iat, err := f.getImportTable32(FirstThunk, maxLen, isOldDelayImport)
	if err != nil {
		return nil, err
	}

	// Some DLLs has IAT or ILT with nil type.
	if len(iat) == 0 && len(ilt) == 0 {
		return nil, ErrDamagedImportTable
	}

	var table []*ThunkData32
	if len(ilt) > 0 {
		table = ilt
	} else if len(iat) > 0 {
		table = iat
	} else {
		return nil, err
	}

	importedFunctions := make([]*ImportFunction, 0)
	numInvalid := uint32(0)
	for idx := uint32(0); idx < uint32(len(table)); idx++ {
		imp := ImportFunction{}
		if table[idx].ImageThunkData.AddressOfData > 0 {
			if table[idx].ImageThunkData.AddressOfData&imageOrdinalFlag32 > 0 {
				imp.ByOrdinal = true
				imp.Ordinal = table[idx].ImageThunkData.AddressOfData & uint32(0xffff)

				if uint32(len(ilt)) > idx {
					imp.OriginalThunkValue = uint64(ilt[idx].ImageThunkData.AddressOfData)
					imp.OriginalThunkRVA = ilt[idx].Offset
				}

				if uint32(len(iat)) > idx {
					imp.ThunkValue = uint64(iat[idx].ImageThunkData.AddressOfData)
					imp.ThunkRVA = iat[idx].Offset
				}

				imp.Name = "#" + strconv.Itoa(int(imp.Ordinal))
			} else {
				imp.ByOrdinal = false
				if isOldDelayImport {
					table[idx].ImageThunkData.AddressOfData -= f.OptionalHeader.(*OptionalHeader32).ImageBase
				}

				// Original Thunk
				if uint32(len(ilt)) > idx {
					imp.OriginalThunkValue = uint64(ilt[idx].ImageThunkData.AddressOfData & addressMask32)
					imp.OriginalThunkRVA = ilt[idx].Offset
				}

				// Thunk
				if uint32(len(iat)) > idx {
					imp.ThunkValue = uint64(iat[idx].ImageThunkData.AddressOfData & addressMask32)
					imp.ThunkRVA = iat[idx].Offset
				}

				// Thunk
				hintNameTableRva := table[idx].ImageThunkData.AddressOfData & addressMask32
				off := f.getOffsetFromRva(hintNameTableRva)
				imp.Hint, err = f.ReadUint16(off)
				if err != nil {
					imp.Hint = ^uint16(0)
				}
				imp.Name = f.getStringAtRVA(table[idx].ImageThunkData.AddressOfData+2, maxImportNameLength)
				if !IsValidFunctionName(imp.Name) {
					imp.Name = "*invalid*"
				}
			}
		}

		if imp.Name == "*invalid*" {
			if numInvalid > 1000 && numInvalid == idx {
				return nil, errors.New(`too many invalid names, aborting parsing`)
			}
			numInvalid++
			continue
		}

		importedFunctions = append(importedFunctions, &imp)
	}

	return importedFunctions, nil
}

func (f *File) readImports64(dt interface{}, maxLen uint32) ([]*ImportFunction, error) {
	if f.OptionalHeader == nil {
		return nil, nil
	}

	var (
		OriginalFirstThunk uint32
		FirstThunk         uint32
		isOldDelayImport   bool
	)

	switch desc := dt.(type) {
	case *ImageImportDirectory:
		OriginalFirstThunk = desc.OriginalFirstThunk
		FirstThunk = desc.FirstThunk
	case *ImageDelayImportDirectory:
		OriginalFirstThunk = desc.ImportNameTableRVA
		FirstThunk = desc.ImportAddressTableRVA
		if desc.Attributes == 0 {
			isOldDelayImport = true
		}
	}

	ilt, err := f.getImportTable64(OriginalFirstThunk, maxLen, isOldDelayImport)
	if err != nil {
		return nil, err
	}

	iat, err := f.getImportTable64(FirstThunk, maxLen, isOldDelayImport)
	if err != nil {
		return nil, err
	}

	// Would crash if IAT or ILT had nil type
	if len(iat) == 0 && len(ilt) == 0 {
		return nil, ErrDamagedImportTable
	}

	var table []*ThunkData64
	if len(ilt) > 0 {
		table = ilt
	} else if len(iat) > 0 {
		table = iat
	} else {
		return nil, err
	}

	importedFunctions := make([]*ImportFunction, 0)
	numInvalid := uint32(0)
	for idx := uint32(0); idx < uint32(len(table)); idx++ {
		imp := ImportFunction{}
		if table[idx].ImageThunkData.AddressOfData > 0 {

			// If imported by ordinal, we will append the ordinal number
			if table[idx].ImageThunkData.AddressOfData&imageOrdinalFlag64 > 0 {
				imp.ByOrdinal = true
				imp.Ordinal = uint32(table[idx].ImageThunkData.AddressOfData) & uint32(0xffff)

				// Original Thunk
				if uint32(len(ilt)) > idx {
					imp.OriginalThunkValue = ilt[idx].ImageThunkData.AddressOfData
					imp.OriginalThunkRVA = ilt[idx].Offset
				}

				// Thunk
				if uint32(len(iat)) > idx {
					imp.ThunkValue = iat[idx].ImageThunkData.AddressOfData
					imp.ThunkRVA = iat[idx].Offset
				}

				imp.Name = "#" + strconv.Itoa(int(imp.Ordinal))

			} else {

				imp.ByOrdinal = false

				if isOldDelayImport {
					table[idx].ImageThunkData.AddressOfData -= f.OptionalHeader.(*OptionalHeader64).ImageBase
				}

				// Original Thunk
				if uint32(len(ilt)) > idx {
					imp.OriginalThunkValue = ilt[idx].ImageThunkData.AddressOfData & addressMask64
					imp.OriginalThunkRVA = ilt[idx].Offset
				}

				// Thunk
				if uint32(len(iat)) > idx {
					imp.ThunkValue = iat[idx].ImageThunkData.AddressOfData & addressMask64
					imp.ThunkRVA = iat[idx].Offset
				}

				hintNameTableRva := table[idx].ImageThunkData.AddressOfData & addressMask64
				off := f.getOffsetFromRva(uint32(hintNameTableRva))
				data := make([]byte, 2)
				_, _ = f.sr.ReadAt(data, int64(off))
				imp.Hint = binary.LittleEndian.Uint16(data)
				imp.Name = f.getStringAtRVA(uint32(table[idx].ImageThunkData.AddressOfData+2), maxImportNameLength)
				if !IsValidFunctionName(imp.Name) {
					imp.Name = "*invalid*"
				}
			}
		}

		if imp.Name == "*invalid*" {
			if numInvalid > 1000 && numInvalid == idx {
				return []*ImportFunction{}, errors.New("too many invalid names, aborting parsing")
			}
			numInvalid++
			continue
		}

		importedFunctions = append(importedFunctions, &imp)
	}

	return importedFunctions, nil
}

// ImpHash calculates the import hash.
func (f *File) ImpHash() (string, error) {
	if len(f.Imports) == 0 {
		return "", errors.New("no imports found")
	}

	extensions := []string{"ocx", "sys", "dll"}
	var normalizedImports []string

	for _, imp := range f.Imports {
		var libName string
		parts := strings.Split(imp.Name, ".")
		if len(parts) == 2 && stringInSlice(strings.ToLower(parts[1]), extensions) {
			libName = parts[0]
		} else {
			libName = imp.Name
		}

		libName = strings.ToLower(libName)

		for _, function := range imp.Functions {
			var funcName string
			if function.ByOrdinal {
				funcName = OrdLookup(imp.Name, uint64(function.Ordinal), true)
			} else {
				funcName = function.Name
			}

			if funcName == "" {
				continue
			}

			impStr := fmt.Sprintf("%s.%s", libName, strings.ToLower(funcName))
			normalizedImports = append(normalizedImports, impStr)
		}
	}
	h := md5.New()
	_, _ = io.WriteString(h, strings.Join(normalizedImports, ","))
	return hex.EncodeToString(h.Sum(nil)), nil
}
