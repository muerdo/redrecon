package main

import (
	"testing"
)

func TestIsSupportedDistro(t *testing.T) {
	testCases := []struct {
		name        string
		osRelease   string
		expectError bool
		errorMsg    string
	}{
		{
			name: "Kali Linux",
			osRelease: `PRETTY_NAME="Kali GNU/Linux Rolling"
ID=kali
VERSION_ID="2023.3"`,
			expectError: false,
		},
		{
			name: "Parrot OS",
			osRelease: `PRETTY_NAME="Parrot OS 5.3"
ID=parrot
ID_LIKE=debian`,
			expectError: false,
		},
		{
			name: "Parrot OS com aspas",
			osRelease: `PRETTY_NAME="Parrot OS 5.3"
ID="parrot"
ID_LIKE=debian`,
			expectError: false,
		},
		{
			name: "Ubuntu (Não suportado)",
			osRelease: `PRETTY_NAME="Ubuntu 22.04.3 LTS"
ID=ubuntu
VERSION_ID="22.04"`,
			expectError: true,
			errorMsg:    "unsupported Linux distribution. Please run on Parrot or Kali Linux",
		},
		{
			name:        "Conteúdo vazio",
			osRelease:   ``,
			expectError: true,
			errorMsg:    "unsupported Linux distribution. Please run on Parrot or Kali Linux",
		},
		{
			name: "Sem linha de ID",
			osRelease: `PRETTY_NAME="Some Linux"
VERSION="1.0"`,
			expectError: true,
			errorMsg:    "unsupported Linux distribution. Please run on Parrot or Kali Linux",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.osRelease)

			err := isSupportedDistro(content)

			if tc.expectError {
				if err == nil {
					t.Errorf("esperava um erro, mas não recebi nenhum")
				} else if err.Error() != tc.errorMsg {
					t.Errorf("esperava a mensagem de erro '%s', mas recebi '%s'", tc.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("não esperava um erro, mas recebi: %v", err)
				}
			}
		})
	}
}
