# AStRA Toolchain (Go)

Go implementation of the AStRA pipeline:

- `astra parse`    → normalize raw logs
- `astra map`      → map normalized events to AStRA schema
- `astra graph`    → build a DAG and export JSON
- `astra risk`     → compute risk metrics (centrality, articulation, topo)
- `astra condense` → group nodes for simpler views

## Quickstart

```bash
cd astra-go
go build ./cmd/astra
./astra parse   -f git -i "git repo URL" -o out/parsed.json
./astra map     -i out/parsed.json  -o out/astra-graph.json
./astra graph   -i out/graph.json 
./astra risk    -i out/graph.json -r out/risk.json --paths-from Principal --paths-to Artifact
./astra condense -i out/graph.json -o out/condensed.json --group-by phase
./astra viz -i out/graph.json -o out/graph.dot  
dot -Tsvg out/graph.dot -o out/graph.svg  
```

