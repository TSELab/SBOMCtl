package mapper

import (
	"sort"

	"github.com/abuishgair/astra/internal/graph"
	"github.com/abuishgair/astra/internal/parser"
)

// ToAstraGraph converts parser.Mapped ([]Record) into a typed graph.AstraGraph.
// Relations emitted:
//
//	principal --uses--> resource
//	resource  --carries_out--> step
//	step  --consumes--> artifact
//	step      --produces--> artifact
func ToAstraGraph(m parser.Mapped) graph.AstraGraph {
	arts := map[string]graph.Artifact{}
	steps := map[string]graph.Step{}
	princs := map[string]graph.Principal{}
	resources := map[string]graph.Resource{}
	edges := map[string]graph.Edge{}

	addEdge := func(src, dst, rel string, md map[string]string) {
		if src == "" || dst == "" || rel == "" {
			return
		}
		k := src + "|" + rel + "|" + dst
		if _, ok := edges[k]; ok {
			return
		}
		edges[k] = graph.Edge{Source: src, Target: dst, Relation: rel}
		// If we add Edge.Metadata later, we can assign md here.
		_ = md
	}

	for _, rec := range m.Mapped {
		// --- Principal ---
		if rec.Principal.ID != "" {
			if _, ok := princs[rec.Principal.ID]; !ok {
				md := cloneMap(rec.Principal.Attrs)
				if md == nil {
					md = map[string]string{}
				}

				princs[rec.Principal.ID] = graph.Principal{
					ID:       rec.Principal.ID,
					Trust:    "unknown",
					Builder:  "",
					Name:     rec.Principal.Label,
					Metadata: md,
				}
			}
		}

		// --- Step ---
		if rec.Step.ID != "" {
			if _, ok := steps[rec.Step.ID]; !ok {
				md := cloneMap(rec.Step.Attrs)
				if md == nil {
					md = map[string]string{}
				}
				//TODO add environment
				steps[rec.Step.ID] = graph.Step{
					ID:        rec.Step.ID,
					Command:   normalizeStepCommand(md),
					Timestamp: normalizeTimestamp(md), // expects env["time"] if present
					Arch:      normalizeStepArch(md),
					Metadata:  md,
				}
			}
		}

		// --- Resources ---

		for _, r := range rec.Resources {
			if r.ID == "" {
				continue
			}
			if _, ok := resources[r.ID]; !ok {
				resources[r.ID] = graph.Resource{
					ID:     r.ID,
					Type:   normalizeResourceType(r),
					URI:    normalizeResourceURI(r),
					Format: normalizeResourceFormat(r),
				}
			}
		}

		// --- Artifacts (In) ---
		for _, it := range rec.ArtifactsIn {
			if it.ID == "" {
				continue
			}
			if _, ok := arts[it.ID]; !ok {
				arts[it.ID] = normalizeArtifact(it)
			}
			addEdge(rec.Step.ID, it.ID, "consumes", nil)
		}

		// --- Artifacts (Out) ---
		for _, it := range rec.ArtifactsOut {
			if it.ID == "" {
				continue
			}
			if _, ok := arts[it.ID]; !ok {
				arts[it.ID] = normalizeArtifact(it)
			}
			addEdge(rec.Step.ID, it.ID, "produces", nil)
		}

		// --- Edges: principal/resource/step ---

		for _, r := range rec.Resources {
			addEdge(rec.Principal.ID, r.ID, "uses", nil)
			addEdge(r.ID, rec.Step.ID, "carries_out", nil)
		}

	}

	// Materialize deterministic slices.
	out := graph.AstraGraph{}

	for _, a := range arts {
		out.Artifacts = append(out.Artifacts, a)
	}
	for _, s := range steps {
		out.Steps = append(out.Steps, s)
	}
	for _, p := range princs {
		out.Principals = append(out.Principals, p)
	}
	for _, r := range resources {
		out.Resources = append(out.Resources, r)
	}
	for _, e := range edges {
		out.Edges = append(out.Edges, e)
	}
	// Ensure deterministic, ordering of nodes and edges.
	sort.Slice(out.Artifacts, func(i, j int) bool { return out.Artifacts[i].ID < out.Artifacts[j].ID })
	sort.Slice(out.Steps, func(i, j int) bool { return out.Steps[i].ID < out.Steps[j].ID })
	sort.Slice(out.Principals, func(i, j int) bool { return out.Principals[i].ID < out.Principals[j].ID })
	sort.Slice(out.Resources, func(i, j int) bool { return out.Resources[i].ID < out.Resources[j].ID })
	sort.Slice(out.Edges, func(i, j int) bool {
		if out.Edges[i].Source != out.Edges[j].Source {
			return out.Edges[i].Source < out.Edges[j].Source
		}
		if out.Edges[i].Relation != out.Edges[j].Relation {
			return out.Edges[i].Relation < out.Edges[j].Relation
		}
		return out.Edges[i].Target < out.Edges[j].Target
	})

	return out
}
