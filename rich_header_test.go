package pe

import (
	"testing"
)

func TestFile_RichHeaderHash(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "testfile/Notepad.exe",
			want: "d4402332a00c5ffa64df7c83ee613640",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFile(tt.name)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			if got := f.RichHeaderHash(); got != tt.want {
				t.Errorf("File.RichHeaderHash() = %v, want %v", got, tt.want)
			}
		})
	}
}
