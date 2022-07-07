package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"

	"github.com/h2non/filetype"
	pefile "github.com/wanglei-coder/pefile"
)

var filename string

func init() {
	flag.StringVar(&filename, "filename", "", "Please enter the file path")
	flag.Parse()
}

type Info struct {
	MachineType     uint16
	EntryPoint      uint32
	CompilationTime uint32
	ImpHash         string
	RichHeaderHash  string
	Authentihash    string
	Exports         string
	Imports         string
	Overlay         *Overlay
	Sections        []*Section
	ResourceDetails []*ResourceDetail
}

type Overlay struct {
	MD5      string
	FileType string
	Offset   uint64
	Size     int64
	Chi2     float64
	Entropy  float64
}

type Section struct {
	Name           string
	MD5            string
	Flags          string
	RawSize        uint32
	VirtualAddress uint32
	VirtualSize    uint32
	Entropy        float64
}

type ResourceDetail struct {
	Language string
	Type     string
	FileType string
	SHA256   string
	Chi2     float64
	Entropy  float64
}

func getSections(f *pefile.File) []*Section {
	sections := make([]*Section, 0, f.FileHeader.NumberOfSections)
	for _, s := range f.Sections {
		var section Section
		section.Name = s.Name
		section.RawSize = s.Size
		section.VirtualAddress = s.VirtualAddress
		section.VirtualSize = s.VirtualSize
		section.Flags = s.Flags()
		section.MD5 = s.MD5()
		section.Entropy = s.Entropy()
		sections = append(sections, &section)
	}
	return sections
}

func getResourceDetails(f *pefile.File) []*ResourceDetail {
	resourceDetails := make([]*ResourceDetail, 0)
	for _, resourceType := range f.Resources.Entries {
		resourceTypeName := pefile.GetResourceTypeName(resourceType)
		for _, resourceId := range resourceType.Directory.Entries {
			for _, resourceLang := range resourceId.Directory.Entries {
				rd := new(ResourceDetail)
				resourceDetails = append(resourceDetails, rd)
				rd.Language = pefile.GetSubLangNameForLang(resourceLang.Data.Lang, resourceLang.Data.SubLang)
				rd.Type = resourceTypeName
				data, err := f.GetData(resourceLang.Data.Struct.OffsetToData, resourceLang.Data.Struct.Size)
				if err != nil {
					continue
				}
				rd.SHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
				rd.Entropy = CalculateEntropy(data)
				rd.FileType = GetFileType(data)
			}
		}
	}
	return resourceDetails
}

func getOverlay(f *pefile.File) *Overlay {
	rs := f.GetOverlay()
	if rs == nil {
		return nil
	}

	overlay := Overlay{
		Offset: uint64(f.OverlayOffset),
		Size:   int64(f.GetSize()) - f.OverlayOffset,
	}

	hasher := md5.New()
	var entropyCalculator EntropyCalculator
	ws := io.MultiWriter(hasher, &entropyCalculator)
	_, _ = io.Copy(ws, rs)
	overlay.MD5 = hex.EncodeToString(hasher.Sum(nil))
	overlay.Entropy = entropyCalculator.Sum()

	data := make([]byte, 1024)
	_, _ = rs.ReadAt(data, 0)
	overlay.FileType = GetFileType(data)
	return &overlay
}

func main() {
	f, err := pefile.NewFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if f.OptionalHeader == nil {
		return
	}

	info := Info{
		CompilationTime: f.FileHeader.TimeDateStamp,
		MachineType:     f.FileHeader.Machine,
		RichHeaderHash:  f.RichHeaderHash(),
		Authentihash:    hex.EncodeToString(f.Authentihash()),
		Sections:        getSections(f),
		ResourceDetails: getResourceDetails(f),
		Overlay:         getOverlay(f),
	}

	if f.Is64 {
		info.EntryPoint = f.OptionalHeader.(*pefile.OptionalHeader64).AddressOfEntryPoint
	} else {
		info.EntryPoint = f.OptionalHeader.(*pefile.OptionalHeader32).AddressOfEntryPoint
	}
	info.ImpHash, _ = f.ImpHash()

	data, _ := json.MarshalIndent(&info, "", "    ")
	fmt.Printf("%s\n", data)
}

func GetFileType(data []byte) string {
	kind, _ := filetype.Match(data)
	if kind == filetype.Unknown {
		return "Data"
	}
	return kind.MIME.Value
}

func CalculateEntropy(data []byte) float64 {
	size := float64(len(data))
	if size == 0.0 {
		return 0.0
	}

	var frequencies [256]uint64
	for _, v := range data {
		frequencies[v]++
	}

	var entropy float64
	for _, p := range frequencies {
		if p > 0 {
			freq := float64(p) / size
			entropy += freq * math.Log2(freq)
		}
	}

	return -entropy
}

type EntropyCalculator struct {
	size        int
	frequencies [256]uint64
}

func (e *EntropyCalculator) Write(p []byte) (n int, err error) {
	e.size += len(p)
	for _, v := range p {
		e.frequencies[v]++
	}
	return len(p), err
}

func (e *EntropyCalculator) Sum() (entropy float64) {
	if e.size == 0 {
		return
	}

	for _, p := range e.frequencies {
		if p > 0 {
			freq := float64(p) / float64(e.size)
			entropy += freq * math.Log2(freq)
		}
	}
	return -entropy
}
