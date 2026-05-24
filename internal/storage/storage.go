package storage

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"macftpd/internal/auth"
)

var ErrOutsideRoot = errors.New("path escapes storage root")

type Root struct {
	Base       string
	PublicDir  string
	DropboxDir string
	Ignore     []string
}

type Entry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	IsDir   bool      `json:"is_dir"`
	ModTime time.Time `json:"mod_time"`
}

type CopyOptions struct {
	Deduplicate bool
	Overwrite   bool
}

type CopyResult struct {
	Files    int    `json:"files"`
	Bytes    int64  `json:"bytes"`
	Strategy string `json:"strategy"`
}

func New(base, publicDir, dropboxDir string, ignore []string) (*Root, error) {
	abs, err := filepath.Abs(base)
	if err != nil {
		return nil, err
	}
	r := &Root{Base: filepath.Clean(abs), PublicDir: cleanName(publicDir), DropboxDir: cleanName(dropboxDir), Ignore: normalizeIgnore(ignore)}
	if err := os.MkdirAll(r.Base, 0o750); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Root) Resolve(user auth.User, cwd, requested string) (string, string, error) {
	home := cleanVirtual(user.Home)
	if requested == "" {
		requested = cwd
	}
	var virtual string
	if strings.HasPrefix(requested, "/") {
		virtual = cleanVirtual(requested)
	} else {
		virtual = cleanVirtual(filepath.Join(cwd, requested))
	}
	realVirtual := r.mountVirtual(user, home, virtual)
	if home != "/" && virtual != home && !strings.HasPrefix(virtual, home+"/") {
		return "", "", ErrOutsideRoot
	}
	if r.IsIgnoredVirtual(realVirtual) {
		return "", "", ErrOutsideRoot
	}
	realPath, err := r.realFromVirtual(realVirtual)
	if err != nil {
		return "", "", ErrOutsideRoot
	}
	return realPath, virtual, nil
}

func (r *Root) ResolveAdmin(virtual string) (string, string, error) {
	virtual = cleanVirtual(virtual)
	if r.IsIgnoredVirtual(virtual) {
		return "", "", ErrOutsideRoot
	}
	realPath, err := r.realFromVirtual(virtual)
	if err != nil {
		return "", "", ErrOutsideRoot
	}
	return realPath, virtual, nil
}

func (r *Root) EnsureUserHome(user auth.User) error {
	home, _, err := r.Resolve(user, "/", user.Home)
	if err != nil {
		return err
	}
	if err := r.MkdirAll(home, 0o750); err != nil {
		return err
	}
	if user.Permissions.Dropbox {
		return r.MkdirAll(filepath.Join(r.Base, r.DropboxDir, user.Username), 0o750)
	}
	return nil
}

func (r *Root) List(realDir, virtualDir string) ([]Entry, error) {
	root, err := os.OpenRoot(r.Base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	rel, err := r.relFromReal(realDir)
	if err != nil {
		return nil, err
	}
	items, err := fs.ReadDir(root.FS(), filepath.ToSlash(rel))
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(items))
	for _, item := range items {
		virtual := pathJoinVirtual(virtualDir, item.Name())
		if r.IsIgnoredVirtual(virtual) {
			continue
		}
		info, err := item.Info()
		if err != nil {
			continue
		}
		entries = append(entries, entryFromInfo(info, virtual))
	}
	return entries, nil
}

func (r *Root) ListForUser(user auth.User, realDir, virtualDir string) ([]Entry, error) {
	entries, err := r.List(realDir, virtualDir)
	if err != nil {
		return nil, err
	}
	home := cleanVirtual(user.Home)
	if virtualDir != home {
		return entries, nil
	}
	if user.Permissions.Public {
		entries = r.appendVirtualMount(entries, "public", pathJoinVirtual(home, "public"), filepath.Join(r.Base, r.PublicDir))
	}
	if user.Permissions.Dropbox {
		dropboxReal := filepath.Join(r.Base, r.DropboxDir, user.Username)
		_ = r.MkdirAll(dropboxReal, 0o750)
		entries = r.appendVirtualMount(entries, "dropbox", pathJoinVirtual(home, "dropbox"), dropboxReal)
	}
	return entries, nil
}

func (r *Root) IsPublicReal(realPath string) bool {
	realPath = filepath.Clean(realPath)
	publicRoot := filepath.Join(r.Base, r.PublicDir)
	return realPath == publicRoot || strings.HasPrefix(realPath, publicRoot+string(os.PathSeparator))
}

func (r *Root) IsIgnoredVirtual(virtual string) bool {
	virtual = cleanVirtual(virtual)
	if virtual == "/" {
		return false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(virtual, "/"), "/") {
		for _, pattern := range r.Ignore {
			matched, err := filepath.Match(pattern, segment)
			if err == nil && matched {
				return true
			}
			if err != nil && pattern == segment {
				return true
			}
		}
	}
	return false
}

func entryFromInfo(info fs.FileInfo, virtual string) Entry {
	return Entry{
		Name:    info.Name(),
		Path:    virtual,
		Size:    info.Size(),
		Mode:    info.Mode().String(),
		IsDir:   info.IsDir(),
		ModTime: info.ModTime(),
	}
}

func (r *Root) appendVirtualMount(entries []Entry, name, virtual, real string) []Entry {
	for _, entry := range entries {
		if entry.Name == name {
			return entries
		}
	}
	info, err := r.Stat(real)
	if err != nil {
		_ = r.MkdirAll(real, 0o750)
		info, err = r.Stat(real)
		if err != nil {
			return entries
		}
	}
	return append(entries, entryFromInfo(namedInfo{FileInfo: info, name: name}, virtual))
}

type namedInfo struct {
	fs.FileInfo
	name string
}

func (n namedInfo) Name() string { return n.name }

func (r *Root) mountVirtual(user auth.User, home, virtual string) string {
	if home == "" {
		home = "/"
	}
	if user.Permissions.Public {
		if suffix, ok := mountSuffix(home, virtual, "public"); ok {
			return cleanVirtual(filepath.Join("/", r.PublicDir, suffix))
		}
	}
	if user.Permissions.Dropbox {
		if suffix, ok := mountSuffix(home, virtual, "dropbox"); ok {
			return cleanVirtual(filepath.Join("/", r.DropboxDir, user.Username, suffix))
		}
	}
	return virtual
}

func mountSuffix(home, virtual, mount string) (string, bool) {
	mountRoot := pathJoinVirtual(home, mount)
	if virtual == mountRoot {
		return "", true
	}
	if strings.HasPrefix(virtual, mountRoot+"/") {
		return strings.TrimPrefix(virtual, mountRoot+"/"), true
	}
	return "", false
}

func (r *Root) realFromVirtual(virtual string) (string, error) {
	realPath := filepath.Join(r.Base, strings.TrimPrefix(virtual, "/"))
	realPath = filepath.Clean(realPath)
	if realPath != r.Base && !strings.HasPrefix(realPath, r.Base+string(os.PathSeparator)) {
		return "", ErrOutsideRoot
	}
	return realPath, nil
}

func (r *Root) relFromReal(realPath string) (string, error) {
	realPath = filepath.Clean(realPath)
	if realPath != r.Base && !strings.HasPrefix(realPath, r.Base+string(os.PathSeparator)) {
		return "", ErrOutsideRoot
	}
	rel, err := filepath.Rel(r.Base, realPath)
	if err != nil {
		return "", ErrOutsideRoot
	}
	if rel == "." || rel == "" {
		return ".", nil
	}
	return rel, nil
}

func (r *Root) Stat(realPath string) (fs.FileInfo, error) {
	root, err := os.OpenRoot(r.Base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	rel, err := r.relFromReal(realPath)
	if err != nil {
		return nil, err
	}
	return root.Stat(rel)
}

func (r *Root) Open(realPath string) (*os.File, error) {
	root, err := os.OpenRoot(r.Base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	rel, err := r.relFromReal(realPath)
	if err != nil {
		return nil, err
	}
	return root.Open(rel)
}

func (r *Root) OpenFile(realPath string, flag int, perm fs.FileMode) (*os.File, error) {
	root, err := os.OpenRoot(r.Base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	rel, err := r.relFromReal(realPath)
	if err != nil {
		return nil, err
	}
	return root.OpenFile(rel, flag, perm)
}

func (r *Root) MkdirAll(realPath string, perm fs.FileMode) error {
	root, err := os.OpenRoot(r.Base)
	if err != nil {
		return err
	}
	defer root.Close()
	rel, err := r.relFromReal(realPath)
	if err != nil {
		return err
	}
	return root.MkdirAll(rel, perm)
}

func (r *Root) MkdirAllParent(realPath string, perm fs.FileMode) error {
	return r.MkdirAll(filepath.Dir(realPath), perm)
}

func (r *Root) Remove(realPath string) error {
	root, err := os.OpenRoot(r.Base)
	if err != nil {
		return err
	}
	defer root.Close()
	rel, err := r.relFromReal(realPath)
	if err != nil {
		return err
	}
	return root.Remove(rel)
}

func (r *Root) RemoveAll(realPath string) error {
	root, err := os.OpenRoot(r.Base)
	if err != nil {
		return err
	}
	defer root.Close()
	rel, err := r.relFromReal(realPath)
	if err != nil {
		return err
	}
	return root.RemoveAll(rel)
}

func (r *Root) Rename(oldPath, newPath string) error {
	root, err := os.OpenRoot(r.Base)
	if err != nil {
		return err
	}
	defer root.Close()
	oldRel, err := r.relFromReal(oldPath)
	if err != nil {
		return err
	}
	newRel, err := r.relFromReal(newPath)
	if err != nil {
		return err
	}
	return root.Rename(oldRel, newRel)
}

func (r *Root) Copy(srcPath, dstPath string, opts CopyOptions) (CopyResult, error) {
	info, err := r.Stat(srcPath)
	if err != nil {
		return CopyResult{}, err
	}
	if dstPath == r.Base {
		return CopyResult{}, ErrOutsideRoot
	}
	if info.IsDir() {
		return r.copyDir(srcPath, dstPath, opts)
	}
	return r.copyFile(srcPath, dstPath, opts)
}

func (r *Root) copyDir(srcPath, dstPath string, opts CopyOptions) (CopyResult, error) {
	srcPath = filepath.Clean(srcPath)
	dstPath = filepath.Clean(dstPath)
	if dstPath == srcPath || strings.HasPrefix(dstPath, srcPath+string(os.PathSeparator)) {
		return CopyResult{}, errors.New("destination cannot be inside source folder")
	}
	if !opts.Overwrite {
		if _, err := r.Stat(dstPath); err == nil {
			return CopyResult{}, errors.New("destination exists")
		}
	}
	if err := r.MkdirAll(dstPath, 0o750); err != nil {
		return CopyResult{}, err
	}
	entries, err := r.List(srcPath, "/")
	if err != nil {
		return CopyResult{}, err
	}
	result := CopyResult{}
	for _, entry := range entries {
		childSrc := filepath.Join(srcPath, entry.Name)
		childDst := filepath.Join(dstPath, entry.Name)
		child, err := r.Copy(childSrc, childDst, opts)
		if err != nil {
			return result, err
		}
		result.Files += child.Files
		result.Bytes += child.Bytes
		switch {
		case result.Strategy == "":
			result.Strategy = child.Strategy
		case child.Strategy != "" && result.Strategy != child.Strategy:
			result.Strategy = "mixed"
		}
	}
	if result.Strategy == "" {
		result.Strategy = "copy"
	}
	return result, nil
}

func (r *Root) copyFile(srcPath, dstPath string, opts CopyOptions) (CopyResult, error) {
	info, err := r.Stat(srcPath)
	if err != nil {
		return CopyResult{}, err
	}
	if info.IsDir() {
		return CopyResult{}, errors.New("source is a directory")
	}
	if !opts.Overwrite {
		if _, err := r.Stat(dstPath); err == nil {
			return CopyResult{}, errors.New("destination exists")
		}
	}
	if err := r.MkdirAllParent(dstPath, 0o750); err != nil {
		return CopyResult{}, err
	}
	if opts.Deduplicate {
		if err := cloneFile(srcPath, dstPath); err == nil {
			return CopyResult{Files: 1, Bytes: info.Size(), Strategy: "clonefile"}, nil
		}
	}
	in, err := r.Open(srcPath)
	if err != nil {
		return CopyResult{}, err
	}
	defer in.Close()
	flag := os.O_CREATE | os.O_WRONLY
	if opts.Overwrite {
		flag |= os.O_TRUNC
	} else {
		flag |= os.O_EXCL
	}
	out, err := r.OpenFile(dstPath, flag, info.Mode().Perm())
	if err != nil {
		return CopyResult{}, err
	}
	defer out.Close()
	n, err := io.Copy(out, in)
	if err != nil {
		return CopyResult{}, err
	}
	return CopyResult{Files: 1, Bytes: n, Strategy: "copy"}, nil
}

func cleanName(name string) string {
	name = strings.Trim(strings.ReplaceAll(name, "\\", "/"), "/")
	if strings.Contains(name, "/") || name == "" {
		return name
	}
	return name
}

func normalizeIgnore(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern != "" {
			out = append(out, pattern)
		}
	}
	return out
}

func cleanVirtual(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	if p == "" {
		return "/"
	}
	clean := filepath.Clean("/" + strings.TrimPrefix(p, "/"))
	if clean == "." {
		return "/"
	}
	return filepath.ToSlash(clean)
}

func pathJoinVirtual(base, name string) string {
	if base == "/" {
		return "/" + name
	}
	return filepath.ToSlash(filepath.Join(base, name))
}

func WriteFileAtomic(path string, mode fs.FileMode, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp-%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
