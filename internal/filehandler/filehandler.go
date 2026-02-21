package filehandler

import (
	"os"
)

func OpenFile(path string) (*os.File, error) {
	file, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	return file, nil
}
