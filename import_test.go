package pe

import (
	"testing"
)

func TestFile_ImpHash(t *testing.T) {

	tests := []struct {
		name string
		want string
	}{
		{
			name: "test/Notepad.exe",
			want: "0e704f5a960ed2d2941bb74a20316b25",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFile(tt.name)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			got, err := f.ImpHash()
			if err != nil {
				t.Errorf("File.ImpHash() error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("File.ImpHash() = %v, want %v", got, tt.want)
			}
		})
	}
}
