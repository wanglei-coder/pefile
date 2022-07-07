package pe

import (
	"io"
)

type LargestOffsetAndSize struct {
	offset, size uint32
}

func (f *File) getOverlayDataStartOffset() uint32 {
	if f.OptionalHeader == nil {
		return 0
	}

	largest := &LargestOffsetAndSize{offset: 0, size: 0}
	updateIfSumIsLargerAndWithinFile := func(offsetAndSize *LargestOffsetAndSize) *LargestOffsetAndSize {
		sum := offsetAndSize.offset + offsetAndSize.size
		if sum <= f.size && sum > largest.offset+largest.size {
			return offsetAndSize
		}
		return largest
	}

	offsetAndSize := &LargestOffsetAndSize{
		offset: f.DOSHeader.AddressOfNewEXEHeader + 24,
		size:   uint32(f.FileHeader.SizeOfOptionalHeader),
	}
	largest = updateIfSumIsLargerAndWithinFile(offsetAndSize)

	for _, section := range f.Sections {
		offsetAndSize := &LargestOffsetAndSize{
			offset: section.Offset,
			size:   section.Size,
		}
		largest = updateIfSumIsLargerAndWithinFile(offsetAndSize)
	}

	var dds [16]DataDirectory
	switch f.Is64 {
	case true:
		dds = f.OptionalHeader.(*OptionalHeader64).DataDirectory
	case false:
		dds = f.OptionalHeader.(*OptionalHeader32).DataDirectory
	}

	for idx, directory := range dds {
		if idx == ImageDirectoryEntrySecurity {
			continue
		}

		offsetAndSize := &LargestOffsetAndSize{
			offset: f.getOffsetFromRva(directory.VirtualAddress),
			size:   directory.Size,
		}
		largest = updateIfSumIsLargerAndWithinFile(offsetAndSize)
	}

	if f.size-largest.size > largest.offset {
		return largest.offset + largest.size
	}
	return 0
}

func (f *File) GetOverlay() *io.SectionReader {
	f.OverlayOffset = int64(f.getOverlayDataStartOffset())
	if f.OverlayOffset != 0 {
		return io.NewSectionReader(f.sr, f.OverlayOffset, int64(f.size)-f.OverlayOffset)
	}
	return nil
}
