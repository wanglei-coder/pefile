package pe

import (
	"encoding/hex"
	"testing"
)

func TestFile_Authentihash(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "test/Notepad.exe",
			want: "402fa6723792c15707f74a0326129b3b631de762c6181775091ae63ff201607f",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFile(tt.name)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()

			if got := hex.EncodeToString(f.Authentihash()); got != tt.want {
				t.Errorf("File.Authentihash() = %v, want %v", got, tt.want)
			}
		})
	}
}
