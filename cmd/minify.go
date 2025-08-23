package dockertrace

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/docker/docker/api/types/build"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/gofrs/uuid"
	"github.com/nathants/docker-trace/lib"
)

// register the minify command with its args for cli dispatch
func init() {
	lib.Commands["minify"] = minify
	lib.Args["minify"] = minifyArgs{}
}

// holds required input and output container names
type minifyArgs struct {
	ContainerIn  string `arg:"positional,required"`
	ContainerOut string `arg:"positional,required"`
}

// returns human readable description for -h usage
func (minifyArgs) Description() string {
	return "\nminify a container keeping files passed on stdin\n"
}

// entrypoint for minify that parses args and runs pipeline
func minify() {
	var args minifyArgs
	arg.MustParse(&args)
	err := runMinify(args)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
}

// orchestrates export, filter, and build restoring metadata
func runMinify(args minifyArgs) error {
	lib.Logger.Println("start minification", args.ContainerIn, "=>",
		args.ContainerOut)
	ctx := context.Background()
	uid := uuid.Must(uuid.NewV4()).String()
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}
	lib.Logger.Println("created docker client")
	includeExact, err := readIncludeStdin()
	if err != nil {
		return err
	}
	lib.Logger.Println("included paths:", len(includeExact))
	contID, err := createExportContainer(ctx, cli, args.ContainerIn)
	if err != nil {
		return err
	}
	defer func() {
		_ = cli.ContainerRemove(ctx, contID,
			container.RemoveOptions{Force: true})
	}()
	idx, err := indexExport(ctx, cli, contID)
	if err != nil {
		return err
	}
	lib.Logger.Println("indexed export tar")
	parentDirs, fullDirs, includeAll := expandIncludes(idx, includeExact)
	outPath := lib.DataDir() + "/out.tar." + uid
	err = filterExportToTar(ctx, cli, contID, outPath,
		parentDirs, fullDirs, includeAll)
	if err != nil {
		return err
	}
	lib.Logger.Println("finished writing out.tar")
	dfPath := lib.DataDir() + "/Dockerfile." + uid
	err = writeDockerfile(ctx, dfPath, uid, args.ContainerIn)
	if err != nil {
		return err
	}
	lib.Logger.Println("created new dockerfile")
	err = buildFromContext(ctx, cli, dfPath, outPath, uid,
		args.ContainerOut)
	if err != nil {
		return err
	}
	lib.Logger.Println("built minified image")
	if err := os.Remove(outPath); err != nil {
		return err
	}
	if err := os.Remove(dfPath); err != nil {
		return err
	}
	lib.Logger.Println("minification complete")
	return nil
}

// pathSet is a string set used for path membership checks
type pathSet map[string]bool

// reads stdin include list, normalizes, and deduplicates paths
func readIncludeStdin() (pathSet, error) {
	// reads stdin fully, splits, cleans, forces leading slash, dedups
	bytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	result := pathSet{}
	lines := strings.Split(string(bytes), "\n")
	for _, p := range lines {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = filepath.Clean(p)
		p = strings.ReplaceAll(p, "/./", "/")
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		p = strings.TrimRight(p, "/")
		result[p] = true
	}
	return result, nil
}

// creates a stopped container from image for export tar
func createExportContainer(ctx context.Context, cli *client.Client,
	image string) (string, error) {
	cfg := &container.Config{Image: image, Cmd: []string{"/bin/sh", "-c",
		"#"}}
	resp, err := cli.ContainerCreate(ctx, cfg, nil, nil, nil, "")
	if err != nil {
		return "", err
	}
	return resp.ID, nil
}

// exportIndex caches dirs and link relations discovered from export
type exportIndex struct {
	dirs       pathSet
	symlinks   map[string]string
	hardlinks  map[string]string
	rootLinks  pathSet
	loaderLibs pathSet
	shellBins  pathSet
}

// scans export tar once to record dirs, symlinks, hardlinks and extras
func indexExport(ctx context.Context, cli *client.Client,
	contID string) (*exportIndex, error) {
	r, err := cli.ContainerExport(ctx, contID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	idx := &exportIndex{
		dirs:       pathSet{},
		symlinks:   map[string]string{},
		hardlinks:  map[string]string{},
		rootLinks:  pathSet{},
		loaderLibs: pathSet{},
		shellBins:  pathSet{},
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr == nil {
			continue
		}
		p := "/" + strings.ReplaceAll(hdr.Name, "/./", "/")
		p = strings.TrimRight(p, "/")
		base := path.Base(p)
		switch hdr.Typeflag {
		case tar.TypeDir:
			idx.dirs[p] = true
		case tar.TypeSymlink:
			tgt := hdr.Linkname
			if !strings.HasPrefix(tgt, "/") {
				tgt = path.Join(path.Dir(p), tgt)
			}
			tgt = filepath.Clean(tgt)
			if !strings.HasPrefix(tgt, "/") {
				tgt = "/" + tgt
			}
			tgt = strings.TrimRight(tgt, "/")
			idx.symlinks[p] = tgt
			if len(strings.Split(p, "/")) == 2 {
				idx.rootLinks[p] = true
			}
		case tar.TypeLink:
			tgt := hdr.Linkname
			if !strings.HasPrefix(tgt, "/") {
				tgt = "/" + tgt
			}
			tgt = filepath.Clean(tgt)
			tgt = strings.TrimRight(tgt, "/")
			idx.hardlinks[p] = tgt
		case tar.TypeReg:
			if strings.Contains(p, "/lib") && strings.HasPrefix(base, "ld-") &&
				strings.Contains(base, ".so") {
				idx.loaderLibs[p] = true
			}
			if (base == "bash" || base == "sh" || base == "env") &&
				strings.Contains(p, "/bin/") {
				idx.shellBins[p] = true
			}
		default:
		}
	}
	return idx, nil
}

// expands includes with parents, extras, and link target closures
func expandIncludes(idx *exportIndex, exact pathSet) (pathSet, pathSet, pathSet) {
	// parentDirs are parent dirs needed for structure only
	parentDirs := pathSet{}
	// fullDirs are explicitly included directories with all contents
	fullDirs := pathSet{}
	includeAll := pathSet{}
	for p := range exact {
		includeAll[p] = true
		// Check if any parent in the path is a symlink
		// If so, we need to include the resolved path too
		parts := strings.Split(strings.TrimLeft(p, "/"), "/")
		currentPath := ""
		for i, part := range parts {
			if i == 0 {
				currentPath = "/" + part
			} else {
				currentPath = currentPath + "/" + part
			}
			target, isSymlink := idx.symlinks[currentPath]
			if isSymlink && i < len(parts)-1 {
				// This is a symlink in the middle of our path
				// Resolve the rest of the path through the symlink
				remainingPath := "/" + strings.Join(parts[i+1:], "/")
				if !strings.HasPrefix(target, "/") {
					// Relative symlink
					target = path.Join(path.Dir(currentPath), target)
				}
				resolvedPath := path.Join(target, remainingPath)
				resolvedPath = path.Clean(resolvedPath)
				// Include the resolved path and follow its symlinks
				includeAll[resolvedPath] = true
				addLinkClosure(resolvedPath, includeAll, idx.symlinks, idx.hardlinks)
				break
			}
		}
		parents := parentsOf(p)
		for _, d := range parents {
			parentDirs[d] = true
		}
	}
	for p := range idx.rootLinks {
		includeAll[p] = true
	}
	for p := range idx.loaderLibs {
		includeAll[p] = true
	}
	for p := range idx.shellBins {
		includeAll[p] = true
	}
	// Include symlinks that point to loader libraries
	for symlink, target := range idx.symlinks {
		// Check if target resolves to a loader lib
		resolvedTarget := target
		if !strings.HasPrefix(resolvedTarget, "/") {
			resolvedTarget = path.Join(path.Dir(symlink), resolvedTarget)
		}
		resolvedTarget = path.Clean(resolvedTarget)
		if idx.loaderLibs[resolvedTarget] {
			includeAll[symlink] = true
		}
		// Also check if the symlink name matches the loader pattern
		base := path.Base(symlink)
		if strings.Contains(symlink, "/lib") && strings.Contains(base, "ld-linux") {
			includeAll[symlink] = true
		}
	}
	for p := range exact {
		addLinkClosure(p, includeAll, idx.symlinks, idx.hardlinks)
	}
	// Follow symlinks for all included paths to ensure targets are included
	// Need to iterate until no new paths are added
	changed := true
	for changed {
		changed = false
		for p := range includeAll {
			if target, isSymlink := idx.symlinks[p]; isSymlink {
				if !includeAll[target] {
					includeAll[target] = true
					changed = true
					addLinkClosure(target, includeAll, idx.symlinks, idx.hardlinks)
				}
			}
			if target, isHardlink := idx.hardlinks[p]; isHardlink {
				if !includeAll[target] {
					includeAll[target] = true
					changed = true
				}
			}
		}
	}
	// ensure parents of all included paths are created
	// but if a parent is a symlink, include it fully
	for p := range includeAll {
		parents := parentsOf(p)
		for _, d := range parents {
			if target, isSymlink := idx.symlinks[d]; isSymlink {
				// Parent is a symlink, must include it fully
				includeAll[d] = true
				// Resolve target path
				if !strings.HasPrefix(target, "/") {
					// Relative symlink, resolve from parent of symlink
					target = path.Join(path.Dir(d), target)
				}
				// Ensure symlink target's parent directories exist
				for _, pd := range parentsOf(target) {
					parentDirs[pd] = true
				}
				// Map the rest of the path after the symlink to the target
				// e.g., /lib/x86_64-linux-gnu when /lib -> usr/lib
				// means we need /usr/lib/x86_64-linux-gnu
				remainingPath := strings.TrimPrefix(p, d)
				if remainingPath != "" && remainingPath != p {
					targetPath := path.Join(target, remainingPath)
					for _, pd := range parentsOf(targetPath) {
						parentDirs[pd] = true
					}
				}
				addLinkClosure(d, includeAll, idx.symlinks, idx.hardlinks)
			} else {
				parentDirs[d] = true
			}
		}
	}
	// if an included path is a directory, mark it as fully included
	for p := range exact {
		if idx.dirs[p] {
			fullDirs[p] = true
			for s, tgt := range idx.symlinks {
				if strings.HasPrefix(s, p+"/") {
					includeAll[s] = true
					addLinkClosure(tgt, includeAll, idx.symlinks,
						idx.hardlinks)
				}
			}
			for s, tgt := range idx.hardlinks {
				if strings.HasPrefix(s, p+"/") {
					includeAll[s] = true
					includeAll[tgt] = true
				}
			}
		}
	}
	return parentDirs, fullDirs, includeAll
}

// follows link chains to include both link and ultimate target
func addLinkClosure(p string, out pathSet, syms, hard map[string]string) {
	seen := pathSet{}
	cur := p
	for range 16 {
		if seen[cur] {
			return
		}
		seen[cur] = true
		tgt, ok := syms[cur]
		if ok {
			out[cur] = true
			out[tgt] = true
			cur = tgt
			continue
		}
		tgt, ok = hard[cur]
		if ok {
			out[cur] = true
			out[tgt] = true
			cur = tgt
			continue
		}
		return
	}
}

// returns parent directories for a path excluding root
func parentsOf(p string) []string {
	var dirs []string
	parts := strings.Split(strings.TrimLeft(p, "/"), "/")
	for i := 1; i < len(parts); i++ {
		d := "/" + path.Join(parts[:i]...)
		d = strings.TrimRight(d, "/")
		dirs = append(dirs, d)
	}
	return dirs
}

// writes a filtered export tar honoring includes with proper link order
func filterExportToTar(ctx context.Context, cli *client.Client,
	contID, outPath string, parentDirs, fullDirs, include pathSet) error {
	r, err := cli.ContainerExport(ctx, contID)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	w, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	defer func() {
		_ = tw.Close()
		_ = w.Close()
	}()
	emitted := pathSet{}
	var pending []tar.Header
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr == nil {
			continue
		}
		p := "/" + strings.ReplaceAll(hdr.Name, "/./", "/")
		p = strings.TrimRight(p, "/")
		ok := include[p]
		if !ok {
			// Check if it's under a fully included directory
			for d := range fullDirs {
				if strings.HasPrefix(p, d+"/") || p == d {
					ok = true
					break
				}
			}
		}
		if !ok {
			// Check if it's a parent directory (structure only)
			if parentDirs[p] && hdr.Typeflag == tar.TypeDir {
				ok = true
			}
		}
		if !ok {
			continue
		}
		// ensure we write directories and symlinks immediately
		switch hdr.Typeflag {
		case tar.TypeDir, tar.TypeSymlink:
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			emitted[p] = true
			continue
		case tar.TypeLink:
			// delay hardlinks until target likely emitted
			pending = append(pending, *hdr)
			continue
		case tar.TypeReg:
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if _, err := io.Copy(tw, tr); err != nil {
				return err
			}
			emitted[p] = true
			continue
		default:
			// include unknowns by header only
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			emitted[p] = true
			continue
		}
	}
	// flush pending hardlinks after files are emitted
	// sort for stable output
	sort.SliceStable(pending, func(i, j int) bool {
		return pending[i].Name < pending[j].Name
	})
	for i := range pending {
		hdr := pending[i]
		// only write if target was emitted or link references itself
		tgt := hdr.Linkname
		if !strings.HasPrefix(tgt, "/") {
			tgt = "/" + tgt
		}
		tgt = strings.TrimRight(filepath.Clean(tgt), "/")
		if emitted[tgt] || tgt == "/"+strings.TrimRight(hdr.Name, "/") {
			if err := tw.WriteHeader(&hdr); err != nil {
				return err
			}
		}
	}
	return nil
}

// writes Dockerfile to add filtered tar and restore metadata
func writeDockerfile(ctx context.Context, dfPath, uid, in string) error {
	f, err := os.OpenFile(dfPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return err
	}
	lines, err := lib.Dockerfile(ctx, in, "")
	if err != nil {
		_ = f.Close()
		return err
	}
	_, err = f.WriteString("FROM scratch\n")
	if err != nil {
		_ = f.Close()
		return err
	}
	_, err = fmt.Fprintf(f, "ADD out.tar.%s /\n", uid)
	if err != nil {
		_ = f.Close()
		return err
	}
	for _, line := range lines {
		_, err := f.WriteString(line + "\n")
		if err != nil {
			_ = f.Close()
			return err
		}
	}
	return f.Close()
}

// streams build context and builds, tagging output image
func buildFromContext(ctx context.Context, cli *client.Client,
	dfPath, outPath, uid, tag string) error {
	pr, pw := io.Pipe()
	go func() {
		// defer func() {}()
		tw := tar.NewWriter(pw)
		fi, err := os.Stat(outPath)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		hdr.Name = "out.tar." + uid
		if err := tw.WriteHeader(hdr); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		rf, err := os.Open(outPath)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(tw, rf); err != nil {
			_ = rf.Close()
			_ = pw.CloseWithError(err)
			return
		}
		_ = rf.Close()
		fi, err = os.Stat(dfPath)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		hdr, err = tar.FileInfoHeader(fi, "")
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		hdr.Name = "Dockerfile." + uid
		if err := tw.WriteHeader(hdr); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		df, err := os.Open(dfPath)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(tw, df); err != nil {
			_ = df.Close()
			_ = pw.CloseWithError(err)
			return
		}
		_ = df.Close()
		if err := tw.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()
	opts := build.ImageBuildOptions{
		NoCache:    true,
		Tags:       []string{tag},
		Dockerfile: "Dockerfile." + uid,
		Remove:     true,
	}
	out, err := cli.ImageBuild(ctx, pr, opts)
	if err != nil {
		return err
	}
	defer func() { _ = out.Body.Close() }()
	scanner := bufio.NewScanner(out.Body)
	val := make(map[string]string)
	for scanner.Scan() {
		if err := json.Unmarshal(scanner.Bytes(), &val); err == nil {
			lib.Logger.Println(strings.Trim(val["stream"], "\n"))
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if val["stream"] != "Successfully tagged "+tag+"\n" {
		return fmt.Errorf("error: failed to build %s", tag)
	}
	return nil
}
