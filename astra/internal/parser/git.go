package parser

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/utils/merkletrie"
)

type GitParser struct{}

func MakeArtifactID(repoURL string, commitHash, filePath string) string {
	repoSlug := getRepoSlug(repoURL)
	return fmt.Sprintf("artifact:gitfile:%s@%s:%s", repoSlug, commitHash, filePath)
}

/*
MakeStepID returns namespaced AStRA Step ID for a Git commit.
The function takes a repository URL and a commit hash,
extracts "host/owner/repo" slug, and formats it into an
AStRA step identifier of the form:
step:commit:<host>/<owner>/<repo>@<commit-hash>
This ensures unique, and deterministic step identifiers regardless of how the repository is cloned locally.
StepID: step:commit:github.com/eman/astra-go@84a1aafee95098a14f351d38013f096fe6dc9e58
*/
func MakeStepID(repoURL string, commitHash string) string {
	repoSlug := getRepoSlug(repoURL)
	return fmt.Sprintf("step:commit:%s@%s", repoSlug, commitHash)
}

func MakeCommitArtifactID(repoURL string, commitHash string) string {
	repoSlug := getRepoSlug(repoURL)
	return fmt.Sprintf("artifact:gitcommit:%s@%s", repoSlug, commitHash)
}

/*
Supported URL formats include:
https://github.com/owner/repo.git
https://github.com/owner/repo
git@github.com:owner/repo.git
*/
func getRepoSlug(raw string) string {
	// Handle SSH scp-style: git@github.com:owner/repo.git
	if strings.HasPrefix(raw, "git@") {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) == 2 {
			host := strings.TrimPrefix(parts[0], "git@")
			path := strings.TrimSuffix(parts[1], ".git")
			return host + "/" + path
		}
		return raw
	}

	// Handle real URLs: https://..., ssh://...
	u, err := url.Parse(raw)
	if err == nil && u.Host != "" {
		path := strings.TrimPrefix(u.Path, "/")
		path = strings.TrimSuffix(path, ".git")
		return u.Host + "/" + path
	}

	return raw
}

func GetCommitIO(repo *git.Repository, hash string) (inputs []*object.File, outputs []*object.File, err error) {
	commit, err := repo.CommitObject(plumbing.NewHash(hash))
	if err != nil {
		return nil, nil, err
	}

	currTree, err := commit.Tree()
	if err != nil {
		return nil, nil, err
	}

	var parentTree *object.Tree
	var parentHash plumbing.Hash
	if commit.NumParents() > 0 {
		parent, err := commit.Parent(0)
		if err != nil {
			return nil, nil, err
		}
		parentHash = parent.Hash
		parentTree, err = parent.Tree()
		if err != nil {
			return nil, nil, err
		}
	}

	seenIn := map[string]bool{}
	seenOut := map[string]bool{}

	// Root commit: everything is output
	if parentTree == nil {
		if err := currTree.Files().ForEach(func(f *object.File) error {
			if seenOut[f.Name] {
				return nil
			}
			seenOut[f.Name] = true
			outputs = append(outputs, f)
			return nil
		}); err != nil {
			return nil, nil, err
		}
		return inputs, outputs, nil
	}

	changes, err := object.DiffTree(parentTree, currTree)
	if err != nil {
		return nil, nil, err
	}

	for _, ch := range changes {
		action, _ := ch.Action()

		switch action {
		case merkletrie.Insert:
			path := ch.To.Name
			if seenOut[path] {
				continue
			}
			f, err := currTree.File(path)
			if err != nil {
				// submodule/symlink/rename edge-case; can't fetch file blob
				// skip metadata but continue
				continue
			}
			seenOut[path] = true
			outputs = append(outputs, f)

		case merkletrie.Delete:
			path := ch.From.Name
			if seenIn[path] {
				continue
			}
			f, err := parentTree.File(path)
			if err != nil {
				return nil, nil, err
			}
			seenIn[path] = true
			inputs = append(inputs, f)

		case merkletrie.Modify:
			inPath := ch.From.Name
			outPath := ch.To.Name

			if !seenIn[inPath] {
				fBefore, err := parentTree.File(inPath)
				if err != nil {
					return nil, nil, err
				}
				seenIn[inPath] = true
				inputs = append(inputs, fBefore)
			}

			if !seenOut[outPath] {
				fAfter, err := currTree.File(outPath)
				if err != nil {
					return nil, nil, err
				}
				seenOut[outPath] = true
				outputs = append(outputs, fAfter)
			}
		}
	}

	_ = parentHash // keep to later build artifact IDs for inputs at parent commit
	return inputs, outputs, nil
}

// Parse get repo url, clone it and get git log and output map it into json file
func (p *GitParser) Parse(repoURL string) (Mapped, error) {
	tmpDir := filepath.Join(os.TempDir(), "gitrepo-history")
	_ = os.RemoveAll(tmpDir) // cleanup from previous runs

	fmt.Println("Cloning:", repoURL)
	fmt.Println("Into   :", tmpDir)

	repo, err := git.PlainClone(tmpDir, false, &git.CloneOptions{
		URL:      repoURL,
		Progress: os.Stdout,
	})
	if err != nil {
		return Mapped{}, fmt.Errorf("clone error: %w", err)
	}

	rem, err := repo.Remote("origin")
	if err != nil {
		return Mapped{}, fmt.Errorf("remote error: %w", err)
	}
	remoteURLs := rem.Config().URLs
	if len(remoteURLs) == 0 {
		return Mapped{}, fmt.Errorf("origin remote has no URLs")
	}
	remoteURL := remoteURLs[0]
	fmt.Println("remote:", remoteURL)

	ref, err := repo.Head()
	if err != nil {
		return Mapped{}, fmt.Errorf("head error: %w", err)
	}

	commits, err := repo.Log(&git.LogOptions{From: ref.Hash()})
	if err != nil {
		return Mapped{}, fmt.Errorf("log error: %w", err)
	}

	out := Mapped{
		Source:       "go-git",
		NormalizedAt: time.Now().Unix(),
	}

	err = commits.ForEach(func(c *object.Commit) error {
		rec := Record{
			Step: Item{
				ID:    MakeStepID(remoteURL, c.Hash.String()),
				Label: "Commit",
				Kind:  "step",
				Attrs: map[string]string{
					"phase":   "source",
					"message": strings.TrimSpace(c.Message),
				},
			},
			Principal: Item{
				ID:    "principal:" + c.Author.Email,
				Label: c.Author.Name,
				Kind:  "principal",
				Attrs: map[string]string{"email": c.Author.Email},
			},
		}

		// Compute IO as file objects
		inputs, outputs, err := GetCommitIO(repo, c.Hash.String())
		if err != nil {
			return err
		}

		// Parent hash is needed to version the "before" (input) artifacts
		parentHash := ""
		// Parent commit(s) as input artifacts
		if c.NumParents() > 0 {
			for i := 0; i < c.NumParents(); i++ {
				parent, err := c.Parent(i)
				if err != nil {
					return err
				}
				parentHash = parent.Hash.String()
				rec.ArtifactsIn = append(rec.ArtifactsIn, Item{
					ID:    MakeCommitArtifactID(remoteURL, parentHash),
					Label: parentHash,
					Kind:  "git-commit",
					Attrs: map[string]string{
						"role":  "parent",
						"index": strconv.Itoa(i),
					},
				})
			}
		}

		// ArtifactsIn (before versions)
		// Root commit => parentHash == "" and inputs should be empty.
		// input files are connected to parent 0 only

		for _, f := range inputs {
			if f == nil || parentHash == "" {
				continue
			}
			rec.ArtifactsIn = append(rec.ArtifactsIn, Item{
				ID:    MakeArtifactID(remoteURL, parentHash, f.Name),
				Label: f.Name,
				Kind:  "git-file",
				Attrs: map[string]string{
					"hash": f.Hash.String(),
					"size": strconv.FormatInt(f.Size, 10),
					"mode": f.Mode.String(),
				},
			})
		}

		//add the commit as output artifact
		rec.ArtifactsOut = append(rec.ArtifactsOut, Item{
			ID:    MakeCommitArtifactID(remoteURL, c.Hash.String()),
			Label: c.Hash.String(),
			Kind:  "git-commit",
			Attrs: map[string]string{
				"message": strings.TrimSpace(c.Message),
				"author":  c.Author.Email,
				"time":    strconv.FormatInt(c.Author.When.Unix(), 10), //TODO check format consistency
			},
		})

		// ArtifactsOut (after versions)
		for _, f := range outputs {
			if f == nil {
				continue
			}
			rec.ArtifactsOut = append(rec.ArtifactsOut, Item{
				ID:    MakeArtifactID(remoteURL, c.Hash.String(), f.Name),
				Label: f.Name,
				Kind:  "git-file",
				Attrs: map[string]string{
					"content-hash": f.Hash.String(),
					"size":         strconv.FormatInt(f.Size, 10),
					"mode":         f.Mode.String(),
				},
			})
		}

		// Resources
		rec.Resources = append(rec.Resources, Item{
			ID:    "resource:git",
			Label: "git",
			Kind:  "vcs",
		})

		out.Mapped = append(out.Mapped, rec)
		return nil
	})
	if err != nil {
		return Mapped{}, err
	}

	return out, nil
}
