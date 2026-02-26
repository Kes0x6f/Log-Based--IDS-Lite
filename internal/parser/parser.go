package parser

import "github.com/Kes0x6f/Log-Based--IDS/internal/model"

type Parser interface {
	Parse(filePath string) ([]*model.NormalizedEvent, error)
}
