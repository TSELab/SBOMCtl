package parser

// Parser is the interface every parser must satisfy
type Parser interface {
	Parse(path string) (Mapped, error)
}

type Item struct {
	ID    string            `json:"id"`
	Label string            `json:"label"`
	Kind  string            `json:"kind"`
	Attrs map[string]string `json:"attrs"`
}

type Record struct {
	Step         Item   `json:"step"`
	Principal    Item   `json:"principal"`
	ArtifactsIn  []Item `json:"artifacts_in"`
	ArtifactsOut []Item `json:"artifacts_out"`
	Resources    []Item `json:"resources"`
}

type Mapped struct {
	Mapped       []Record `json:"mapped"`
	Source       string   `json:"source"`
	NormalizedAt int64    `json:"normalized_at"`
}
