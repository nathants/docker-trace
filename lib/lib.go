package lib

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/avast/retry-go"
	"github.com/docker/docker/client"
	"github.com/mattn/go-isatty"
)

func Atoi(x string) int {
	y, err := strconv.Atoi(x)
	if err != nil {
		panic(err)
	}
	return y
}

func DataDir() string {
	dir := fmt.Sprintf("%s/.docker-trace", os.Getenv("HOME"))
	if !Exists(dir) {
		err := os.Mkdir(dir, os.ModePerm)
		if err != nil {
			panic(err)
		}
	}
	return dir
}

var Commands = make(map[string]func())

type ArgsStruct interface {
	Description() string
}

var Args = make(map[string]ArgsStruct)

type Manifest struct {
	Config   string
	Layers   []string
	RepoTags []string
}

type DockerfileHistory struct {
	CreatedBy string `json:"created_by"`
}

type DockerfileConfig struct {
	History []DockerfileHistory `json:"history"`
}

func SignalHandler(cancel func()) {
	c := make(chan os.Signal, 1)
	signal.Reset(os.Interrupt, syscall.SIGTERM)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		// defer func() {}()
		<-c
		cancel()
	}()
}

func functionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

func DropLinesWithAny(s string, tokens ...string) string {
	var lines []string
outer:
	for _, line := range strings.Split(s, "\n") {
		for _, token := range tokens {
			if strings.Contains(line, token) {
				continue outer
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func Pformat(i interface{}) string {
	val, err := json.MarshalIndent(i, "", "    ")
	if err != nil {
		panic(err)
	}
	return string(val)
}

func Retry(ctx context.Context, fn func() error) error {
	count := 0
	attempts := 6
	return retry.Do(
		func() error {
			if count != 0 {
				Logger.Printf("retry %d/%d for %v\n", count, attempts-1, functionName(fn))
			}
			count++
			err := fn()
			if err != nil {
				return err
			}
			return nil
		},
		retry.Context(ctx),
		retry.LastErrorOnly(true),
		retry.Attempts(uint(attempts)),
		retry.Delay(150*time.Millisecond),
	)
}

func Assert(cond bool, format string, a ...interface{}) {
	if !cond {
		panic(fmt.Sprintf(format, a...))
	}
}

func Panic1(err error) {
	if err != nil {
		panic(err)
	}
}

func Panic2(x interface{}, e error) interface{} {
	if e != nil {
		Logger.Fatalf("fatal: %s\n", e)
	}
	return x
}

func Contains(parts []string, part string) bool {
	for _, p := range parts {
		if p == part {
			return true
		}
	}
	return false
}

func Chunk(xs []string, chunkSize int) [][]string {
	var xss [][]string
	xss = append(xss, []string{})
	for _, x := range xs {
		xss[len(xss)-1] = append(xss[len(xss)-1], x)
		if len(xss[len(xss)-1]) == chunkSize {
			xss = append(xss, []string{})
		}
	}
	return xss
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func StringOr(s *string, d string) string {
	if s == nil {
		return d
	}
	return *s
}

func color(code int) func(string) string {
	return func(s string) string {
		if isatty.IsTerminal(os.Stdout.Fd()) {
			return fmt.Sprintf("\033[%dm%s\033[0m", code, s)
		}
		return s
	}
}

var (
	Red     = color(31)
	Green   = color(32)
	Yellow  = color(33)
	Blue    = color(34)
	Magenta = color(35)
	Cyan    = color(36)
	White   = color(37)
)

func FindManifest(manifests []Manifest, name string) (Manifest, error) {
	// when pulling a previously unknown image by digest, there will be only one
	if len(manifests) == 1 {
		return manifests[0], nil
	}
	for _, m := range manifests {
		// find by imageID
		if strings.HasPrefix(m.Config, name) {
			return m, nil
		}
		// find by tag
		if strings.Contains(name, ":") {
			for _, tag := range m.RepoTags {
				if tag == name {
					return m, nil
				}
			}
		} else {
			err := fmt.Errorf("name must include a tag or be an imageID, got: %s", name)
			Logger.Println("error:", err)
			return Manifest{}, err
		}
	}
	err := fmt.Errorf(Pformat(manifests) + "\ntag not found in manifest")
	Logger.Println("error:", err)
	return Manifest{}, err
}

func Scan(ctx context.Context, name string, tarball string, checkData bool) ([]*ScanFile, map[string]int, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		Logger.Println("error:", err)
		return nil, nil, err
	}

	// Save image to a buffer first so we can read it twice
	var imageData bytes.Buffer
	if tarball != "" {
		file, err := os.Open(tarball)
		if err != nil {
			Logger.Println("error:", err)
			return nil, nil, err
		}
		defer func() { _ = file.Close() }()
		_, err = io.Copy(&imageData, file)
		if err != nil {
			Logger.Println("error:", err)
			return nil, nil, err
		}
	} else {
		r, err := cli.ImageSave(ctx, []string{name})
		if err != nil {
			Logger.Println("error:", err)
			return nil, nil, err
		}
		defer func() { _ = r.Close() }()
		_, err = io.Copy(&imageData, r)
		if err != nil {
			Logger.Println("error:", err)
			return nil, nil, err
		}
	}

	// First pass: extract manifest to identify layer blobs
	var manifests []Manifest
	layerBlobs := make(map[string]bool)
	tr := tar.NewReader(bytes.NewReader(imageData.Bytes()))
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			Logger.Println("error:", err)
			return nil, nil, err
		}
		if header == nil {
			continue
		}
		if header.Typeflag == tar.TypeReg && header.Name == "manifest.json" {
			var data bytes.Buffer
			_, err := io.Copy(&data, tr)
			if err != nil {
				Logger.Println("error:", err)
				return nil, nil, err
			}
			err = json.Unmarshal(data.Bytes(), &manifests)
			if err != nil {
				Logger.Println("error:", err)
				return nil, nil, err
			}
			// Mark layer blobs for OCI format
			for _, m := range manifests {
				for _, layer := range m.Layers {
					layerBlobs[layer] = true
				}
			}
			break // Found manifest, no need to continue first pass
		}
	}

	// Second pass: process layers
	var files []*ScanFile
	tr = tar.NewReader(bytes.NewReader(imageData.Bytes()))
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			Logger.Println("error:", err)
			return nil, nil, err
		}
		if header == nil {
			continue
		}
		if header.Typeflag == tar.TypeReg && layerBlobs[header.Name] {
			// Handle OCI format with blobs/sha256/* files
			layerFiles, err := ScanLayer(header.Name, tr, checkData)
			if err != nil {
				Logger.Println("error:", err)
				return nil, nil, err
			}
			files = append(files, layerFiles...)
		}
	}

	manifest, err := FindManifest(manifests, name)
	if err != nil {
		Logger.Println("error:", err)
		return nil, nil, err
	}

	layers := make(map[string]int)
	for i, layer := range manifest.Layers {
		layers[layer] = i
	}

	for _, f := range files {
		i, ok := layers[f.Layer]
		if !ok {
			err := fmt.Errorf("error: no layer %s", f.Layer)
			Logger.Println("error:", err)
			return nil, nil, err
		}
		f.LayerIndex = i
		f.Layer = ""
	}

	sort.Slice(files, func(i, j int) bool { return files[i].LayerIndex < files[j].LayerIndex })
	sort.SliceStable(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	// keep only last update to the file, not all updates across all layers
	var result []*ScanFile
	var last *ScanFile
	for _, f := range files {
		if last != nil && f.Path != last.Path {
			result = append(result, last)
		}
		last = f
	}
	if last != nil && (len(result) == 0 || last.Path != result[len(result)-1].Path) {
		result = append(result, last)
	}
	return result, layers, nil
}

type ScanFile struct {
	LayerIndex  int
	Layer       string
	Path        string
	LinkTarget  string
	Mode        fs.FileMode
	Size        int64
	ModTime     time.Time
	Hash        string
	ContentType string
	Uid         int
	Gid         int
}

func ScanLayer(layer string, r io.Reader, checkData bool) ([]*ScanFile, error) {
	var result []*ScanFile
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			Logger.Println("error:", err)
			return nil, err
		}
		if header == nil {
			continue
		}
		switch header.Typeflag {
		case tar.TypeReg:
			var data bytes.Buffer
			contentType := ""
			hash := ""
			if checkData {
				_, err := io.Copy(&data, tr)
				if err != nil {
					Logger.Println("error:", err)
					return nil, err
				}
				contentType = "binary"
				if utf8.Valid(data.Bytes()) {
					contentType = "utf8"
				}
				sum := sha256.Sum256(data.Bytes())
				hash = hex.EncodeToString(sum[:])
			}
			result = append(result, &ScanFile{
				Layer:       layer,
				Path:        "/" + header.Name,
				Mode:        header.FileInfo().Mode(),
				Size:        header.Size,
				ModTime:     header.ModTime,
				Hash:        hash,
				ContentType: contentType,
				Uid:         header.Uid,
				Gid:         header.Gid,
			})
		case tar.TypeSymlink:
			result = append(result, &ScanFile{
				Layer:      layer,
				Path:       "/" + header.Name,
				Mode:       header.FileInfo().Mode(),
				ModTime:    header.ModTime,
				LinkTarget: header.Linkname,
				Uid:        header.Uid,
				Gid:        header.Gid,
			})
		case tar.TypeLink:
			result = append(result, &ScanFile{
				Layer:      layer,
				Path:       "/" + header.Name,
				Mode:       header.FileInfo().Mode(),
				ModTime:    header.ModTime,
				LinkTarget: "/" + header.Linkname, // todo, verify: hard links in docker are always absolute and do not include leading /
				Uid:        header.Uid,
				Gid:        header.Gid,
			})
		case tar.TypeDir:
			result = append(result, &ScanFile{
				Layer:   layer,
				Path:    "/" + header.Name,
				Mode:    header.FileInfo().Mode(),
				ModTime: header.ModTime,
				Uid:     header.Uid,
				Gid:     header.Gid,
			})
		default:
			fmt.Fprintln(os.Stderr, "ignoring tar entry:", Pformat(header))
		}
	}
	return result, nil
}

func Dockerfile(ctx context.Context, name string, tarball string) ([]string, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		Logger.Println("error:", err)
		return nil, err
	}
	var manifests []Manifest
	configs := make(map[string]*DockerfileConfig)
	var r io.ReadCloser
	if tarball != "" {
		r, err = os.Open(tarball)
		if err != nil {
			Logger.Println("error:", err)
			return nil, err
		}
	} else {
		r, err = cli.ImageSave(ctx, []string{name})
		if err != nil {
			Logger.Println("error:", err)
			return nil, err
		}
	}
	defer func() { _ = r.Close() }()
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			Logger.Println("error:", err)
			return nil, err
		}
		if header == nil {
			continue
		}
		switch header.Typeflag {
		case tar.TypeReg:
			if header.Name == "manifest.json" {
				var data bytes.Buffer
				_, err := io.Copy(&data, tr)
				if err != nil {
					Logger.Println("error:", err)
					return nil, err
				}
				err = json.Unmarshal(data.Bytes(), &manifests)
				if err != nil {
					Logger.Println("error:", err)
					return nil, err
				}
			} else if strings.HasSuffix(header.Name, ".json") || strings.HasPrefix(header.Name, "blobs/sha256/") {
				var data bytes.Buffer
				_, err := io.Copy(&data, tr)
				if err != nil {
					Logger.Println("error:", err)
					return nil, err
				}
				config := DockerfileConfig{}
				err = json.Unmarshal(data.Bytes(), &config)
				if err != nil {
					// Skip non-JSON blobs (layer tar files)
					continue
				}
				configs[header.Name] = &config
			}
		default:
		}
	}

	manifest, err := FindManifest(manifests, name)
	if err != nil {
		Logger.Println("error:", err)
		return nil, err
	}

	config, ok := configs[manifest.Config]
	if !ok {
		err := fmt.Errorf("no such config: %s", manifest.Config)
		Logger.Println("error:", err)
		return nil, err
	}

	var result []string

	for _, h := range config.History {
		line := h.CreatedBy
		line = last(strings.Split(line, " #(nop) "))
		line = strings.Split(line, " # buildkit")[0]
		line = strings.TrimLeft(line, " ")
		line = strings.ReplaceAll(line, `" `, `", `)
		regex := regexp.MustCompile(`^[A-Z]`)
		if regex.FindString(line) != "" && !strings.HasPrefix(line, "ADD ") && !strings.HasPrefix(line, "COPY ") && !strings.HasPrefix(line, "RUN ") && !strings.HasPrefix(line, "LABEL ") {
			if strings.HasPrefix(line, "EXPOSE ") && strings.Contains(line, " map[") {
				regex := regexp.MustCompile(`[0-9]+`)
				ports := regex.FindAllString("EXPOSE map[8080/4545]", -1)
				line = "EXPOSE " + strings.Join(ports, " ")
			}
			if strings.HasPrefix(line, "ENV ") {
				parts := strings.SplitN(line, "=", 2)
				line = parts[0] + `="` + parts[1] + `"`
			}
			result = append(result, line)
		}
	}
	return result, nil
}

func Max(i, j int) int {
	if i > j {
		return i
	}
	return j
}

type File struct {
	Syscall string
	Cgroup  string
	Pid     string
	Ppid    string
	Comm    string
	Errno   string
	File    string
}

func FilesParseLine(line string) File {
	parts := strings.Split(line, "\t")
	file := File{}
	if len(parts) != 7 {
		Logger.Printf("skipping bpftrace line: %s\n", line)
		return file
	}
	file.Syscall = parts[0]
	file.Cgroup = parts[1]
	file.Pid = parts[2]
	file.Ppid = parts[3]
	file.Comm = parts[4]
	file.Errno = parts[5]
	file.File = parts[6]
	// sometimes file paths include the fs driver paths
	//
	// /mnt/docker-data/overlay2/1b7b19463b59ac563677fda461918ae2faed45d86000fc68cf0eb8052687c121/merged/etc/hosts
	// /var/lib/docker/zfs/graph/825b1c966c9421a50e0200fe3a9d7fe0beddebdd745ea2b976d4c7cf8d1b2e8e/etc/hosts
	//
	if strings.Contains(file.File, "/overlay2/") {
		file.File = last(strings.Split(file.File, "/overlay2/"))
		parts := strings.Split(file.File, "/")
		if len(parts) > 2 {
			file.File = "/" + strings.Join(parts[2:], "/")
		}
	} else if strings.Contains(file.File, "/zfs/graph/") {
		file.File = last(strings.Split(file.File, "/zfs/graph/"))
		parts := strings.Split(file.File, "/")
		if len(parts) > 1 {
			file.File = "/" + strings.Join(parts[1:], "/")
		}
	}
	//
	return file
}

func last(xs []string) string {
	return xs[len(xs)-1]
}

func FilesHandleLine(cwds, cgroups map[string]string, line string) {
	file := FilesParseLine(line)
	if file.Syscall == "cgroup_mkdir" {
		// track ALL cgroups created after docker-trace starts
		// these will be new containers, not existing system cgroups
		cgroups[file.Cgroup] = file.File
	} else if cgroups[file.Cgroup] != "" && file.File != "" && file.Errno == "0" {
		// pids start at cwd of parent
		_, ok := cwds[file.Pid]
		if !ok {
			_, ok := cwds[file.Ppid]
			if ok {
				cwds[file.Pid] = cwds[file.Ppid]
			} else {
				cwds[file.Pid] = "/"
			}
		}
		// update cwd when chdir succeeds
		if file.Syscall == "chdir" {
			if file.File[:1] == "/" {
				cwds[file.Pid] = file.File
			} else {
				cwds[file.Pid] = path.Join(cwds[file.Pid], file.File)
			}
		}
		// join any relative paths to pid cwd
		if file.File[:1] != "/" {
			cwd, ok := cwds[file.Pid]
			if !ok {
				panic(cwds)
			}
			file.File = path.Join(cwd, file.File)
		}
		//
		// _, _ = fmt.Fprintln(os.Stderr, file.Pid, file.Ppid, fmt.Sprintf("%-40s", file.File), fmt.Sprintf("%-10s", file.Comm), file.Errno, file.Syscall)
		fmt.Println(cgroups[file.Cgroup], file.File)
	}
}
