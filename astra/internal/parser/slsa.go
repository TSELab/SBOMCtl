package parser

import (
	"os"
	"time"
)

type SlsaParser struct{}

func (p *SlsaParser) Parse(path string) (Mapped, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Mapped{}, err
	}
	print(b)

	n := Mapped{Source: "SLSA", NormalizedAt: time.Now().Unix()}

	return n, nil
}
