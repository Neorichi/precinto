package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/precinto/precinto/internal/fsx"
)

const (
	indexVersion = 1
	// maxIndexBytes bounds state/projects/<harness>.json.
	maxIndexBytes = 16 << 20
	// indexLockWait bounds how long Put waits for concurrent writers (each
	// holds the lock for one read, one fsynced write and one rename).
	indexLockWait = 10 * time.Second
)

// indexFile is the on-disk form of the project index.
type indexFile struct {
	V        int       `json:"v"`
	Projects []Project `json:"projects"`
}

func openIndex(dir, harness string) *Index {
	return &Index{Path: filepath.Join(dir, harness+".json")}
}

func (x *Index) path() (string, error) {
	if x == nil || !filepath.IsAbs(x.Path) {
		return "", fmt.Errorf("%w: the index path must be absolute", errInvalid)
	}
	return filepath.Clean(x.Path), nil
}

func (x *Index) all() ([]Project, error) {
	p, err := x.path()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_RDONLY|fsx.ONoFollow|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := fsx.Fstat(f)
	if err != nil {
		return nil, err
	}
	if !st.IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", fsx.ErrUnsafe, filepath.Base(p))
	}
	data, err := io.ReadAll(io.LimitReader(f, maxIndexBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxIndexBytes {
		return nil, fmt.Errorf("ledger: %s is larger than %d bytes", filepath.Base(p), maxIndexBytes)
	}
	var file indexFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("ledger: decode %s: %w", filepath.Base(p), err)
	}
	if file.V != indexVersion {
		return nil, fmt.Errorf("ledger: %s has unknown version %d", filepath.Base(p), file.V)
	}
	return file.Projects, nil
}

func (x *Index) lookup(configDir, slug string) (Project, bool, error) {
	all, err := x.all()
	if err != nil {
		return Project{}, false, err
	}
	configDir = filepath.Clean(configDir)
	for _, p := range all {
		if filepath.Clean(p.ConfigDir) == configDir && p.Slug == slug {
			return p, true, nil
		}
	}
	return Project{}, false, nil
}

// put merges p into the index under a lock file (lock files are never
// deleted, SPEC §10.2): cwds and root ids are unions, a non-empty memory
// directory replaces the recorded one. The file is replaced atomically.
func (x *Index) put(p Project) error {
	path, err := x.path()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(p.ConfigDir) {
		return fmt.Errorf("%w: project config dir must be absolute", errInvalid)
	}
	if err := component("project directory name", p.Slug); err != nil {
		return err
	}
	for _, c := range p.Cwds {
		if !filepath.IsAbs(c) {
			return fmt.Errorf("%w: project cwd must be absolute", errInvalid)
		}
	}
	if p.MemoryDir != "" && !filepath.IsAbs(p.MemoryDir) {
		return fmt.Errorf("%w: memory dir must be absolute", errInvalid)
	}
	if err := mkdirPrivate(filepath.Dir(path)); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), indexLockWait)
	defer cancel()
	lock, err := fsx.WaitLock(ctx, path+".lock", false)
	if err != nil {
		return fmt.Errorf("ledger: lock %s: %w", filepath.Base(path), err)
	}
	defer lock.Unlock()

	all, err := x.all()
	if err != nil {
		return err
	}
	p.ConfigDir = filepath.Clean(p.ConfigDir)
	merged := false
	for i := range all {
		q := &all[i]
		if filepath.Clean(q.ConfigDir) != p.ConfigDir || q.Slug != p.Slug {
			continue
		}
		q.Cwds = union(q.Cwds, p.Cwds)
		q.RootIDs = union(q.RootIDs, p.RootIDs)
		if p.MemoryDir != "" {
			q.MemoryDir = p.MemoryDir
		}
		if q.Harness == "" {
			q.Harness = p.Harness
		}
		merged = true
		break
	}
	if !merged {
		p.Cwds = union(nil, p.Cwds)
		p.RootIDs = union(nil, p.RootIDs)
		all = append(all, p)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].ConfigDir != all[j].ConfigDir {
			return all[i].ConfigDir < all[j].ConfigDir
		}
		return all[i].Slug < all[j].Slug
	})
	data, err := json.Marshal(indexFile{V: indexVersion, Projects: all})
	if err != nil {
		return err
	}
	if len(data) > maxIndexBytes {
		return fmt.Errorf("ledger: %s would exceed %d bytes", filepath.Base(path), maxIndexBytes)
	}
	return fsx.WriteFileAtomic(path, data, 0o600)
}

// union appends to a the values of b it lacks, keeping order; empty values
// are dropped.
func union(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, v := range append(append([]string{}, a...), b...) {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
