package mapper

import (
	"strconv"
	"strings"

	"github.com/abuishgair/astra/internal/graph"
	"github.com/abuishgair/astra/internal/parser"
)

// cloneMap defensively copies a map (so later mutation doesn’t affect source records).
func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// normalizeArtifact converts a parser.Item into a typed graph.Artifact.
// It preserves all attrs in Metadata and additionally extracts Hash/Size when present.
func normalizeArtifact(it parser.Item) graph.Artifact {
	a := graph.Artifact{
		ID:       it.ID,
		Kind:     normalizeArtifactKind(it.Kind),
		Name:     it.Label,
		Version:  extractVersionFromID(it.ID), // explicit version (best-effort)
		Metadata: map[string]string{},
	}

	for k, v := range it.Attrs {
		a.Metadata[k] = v
	}

	// Pull typed fields if present
	if h, ok := it.Attrs["content-hash"]; ok && strings.TrimSpace(h) != "" {
		a.Hash = h
	}
	if s, ok := it.Attrs["size"]; ok && strings.TrimSpace(s) != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			a.Size = n
		}
	}

	return a
}

// normalizeArtifactKind keeps  git-specific kinds by default.
// If we want coarser kinds later, map "git-file"->"file", "git-commit"->"commit".
func normalizeArtifactKind(k string) string {
	k = strings.TrimSpace(k)
	if k == "" {
		return "artifact"
	}
	return k
}

// extractVersionFromID best-effort parses "@<version>" from IDs like:
// artifact:gitfile:<slug>@<hash>:path
// artifact:gitcommit:<slug>@<hash>
// TODO needs fix, look at the output
func extractVersionFromID(id string) string {
	// Find "...@<ver>..."
	at := strings.LastIndex(id, "@")
	if at < 0 || at == len(id)-1 {
		return ""
	}
	rest := id[at+1:]
	// cut at ":" (file path separator) if present
	if i := strings.Index(rest, ":"); i >= 0 {
		return rest[:i]
	}
	return rest
}

func normalizeStepCommand(md map[string]string) string {
	// Keep stable, queryable command values.
	if v, ok := md["command"]; ok && strings.TrimSpace(v) != "" {
		return v
	}
	if v, ok := md["label"]; ok && strings.TrimSpace(v) != "" {
		return v
	}
	return ""
}

func normalizeStepEnviroment(md map[string]string) string {
	// Keep stable, queryable values or leave empty.
	if v, ok := md["enviroment"]; ok && strings.TrimSpace(v) != "" {
		return v
	}
	return ""
}

func normalizeStepArch(md map[string]string) string {

	// Keep it stable; or leave empty
	if v, ok := md["architecture"]; ok && strings.TrimSpace(v) != "" {
		return v
	}
	return ""
}

func normalizeResourceType(r parser.Item) string {
	// parser emits Kind="vcs" for git; keep that if present.
	if strings.TrimSpace(r.Kind) != "" {
		return r.Kind
	}
	return ""
}

func normalizeResourceURI(r parser.Item) string {
	// If we later store URI in attrs, read it here; otherwise empty.
	if r.Attrs != nil {
		if uri, ok := r.Attrs["uri"]; ok && strings.TrimSpace(uri) != "" {
			return uri
		}
	}
	return ""
}

func normalizeResourceFormat(r parser.Item) string {
	// Prefer explicit, else infer.
	if r.Attrs != nil {
		if f, ok := r.Attrs["format"]; ok && strings.TrimSpace(f) != "" {
			return f
		}
	}
	// Git parser resource is git.
	if strings.Contains(strings.ToLower(r.ID), "git") {
		return "git"
	}
	return ""
}

// normalizeTimestamp returns a string timestamp for current graph.Step schema.
// If we later switch to int64 timestamps, change this to return int64.
func normalizeTimestamp(md map[string]string) string {
	if md == nil {
		return ""
	}
	// Prefer unix seconds in md["time"]
	if t, ok := md["time"]; ok && strings.TrimSpace(t) != "" {
		return t
	}
	// Fall back if we ever store other keys
	if t, ok := md["timestamp"]; ok && strings.TrimSpace(t) != "" {
		return t
	}
	return ""
}
