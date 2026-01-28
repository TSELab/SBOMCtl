package parser

import (
	"os"
	"time"
)

type InTotoParser struct{}

func (p *InTotoParser) Parse(path string) (Mapped, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Mapped{}, err
	}
	print(b)
	n := Mapped{Source: "in-toto", NormalizedAt: time.Now().Unix()}

	return n, nil
}
