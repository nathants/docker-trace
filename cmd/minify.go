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
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/docker/docker/api/types/build"
	"github.com/docker/docker/client"
	"github.com/gofrs/uuid"
	"github.com/nathants/docker-trace/lib"
)

func init() {
	lib.Commands["minify"] = minify
	lib.Args["minify"] = minifyArgs{}
}

type minifyArgs struct {
	ContainerIn  string `arg:"positional,required"`
	ContainerOut string `arg:"positional,required"`
}

func (minifyArgs) Description() string {
	return "\nminify a container keeping files passed on stdin\n"
}

func minify() {
	var args minifyArgs
	arg.MustParse(&args)
	//
	lib.Logger.Println("start minification", args.ContainerIn, "=>", args.ContainerOut)
	ctx := context.Background()
	uid := uuid.Must(uuid.NewV4()).String()
	//
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	lib.Logger.Println("created docker client")
	//
	r, err := cli.ImageSave(ctx, []string{args.ContainerIn})
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	w, err := os.OpenFile(lib.DataDir()+"/in.tar."+uid, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	_, err = io.Copy(w, r)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	err = w.Close()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	lib.Logger.Println("saved input container to disk")
	//
	files, layers, err := lib.Scan(ctx, args.ContainerIn, lib.DataDir()+"/in.tar."+uid, false)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	lib.Logger.Println("scanned container")
	//
	includePaths := map[string]interface{}{}
	bytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	for _, path := range strings.Split(string(bytes), "\n") {
		path = strings.Trim(path, " ")
		path = filepath.Clean(path)
		path = strings.ReplaceAll(path, "/./", "/")
		if path != "" {
			includePaths[path] = nil
		}
	}
	lib.Logger.Println("included paths:", len(includePaths))
	//
	includeFiles := make(map[string]*lib.ScanFile)
	var last *lib.ScanFile
	links := make(map[string]string)
	for _, f := range files {
		if f.LinkTarget != "" {
			links[f.Path] = f.LinkTarget
		}
	}
	//
	// recursively resolve all links
	for p := range includePaths {
		last := ""
		for {
			if last == p {
				break // break when no further change
			}
			last = p
			parts := strings.Split(strings.TrimLeft(p, "/"), "/")
			for i := 0; i <= len(parts); i++ {
				subPath := "/" + path.Join(parts[:i]...)
				link, ok := links[subPath]
				if ok {
					if link[:1] != "/" {
						link = path.Join(path.Dir(subPath), link)
					}
					includePaths[subPath] = nil
					includePaths[link] = nil
					for j := range parts[:i] {
						parts[j] = ""
					}
					parts[0] = link
				}
			}
			p2 := path.Join(parts...)
			includePaths[p2] = nil
			p = p2
		}
	}
	lib.Logger.Println("recursively resolved links")
	//
	for _, f := range files {
		f.Path = strings.ReplaceAll(f.Path, "/./", "/")
		_, ok := includePaths[strings.TrimRight(f.Path, "/")]
		if !ok {
			// sometimes files must always be included, here are some hard coded special cases
			atRoot := len(strings.Split(f.Path, "/")) == 2 && f.LinkTarget != ""
			ldSo := strings.Contains(f.Path, "/lib") && strings.HasPrefix(path.Base(f.Path), "ld-") && strings.Contains(f.Path, ".so")
			name := path.Base(f.Path)
			isShell := (name == "bash" || name == "sh" || name == "env") && strings.Contains(f.Path, "/bin/")
			if !(atRoot || ldSo || isShell) {
				continue
			}
			includePaths[f.Path] = nil
		}
		if last != nil && f.Path != last.Path {
			includeFiles[last.Path] = last
		}
		last = f
	}
	includeFiles[last.Path] = last
	lib.Logger.Println("update include paths for ld-*.so and symlinks at root")
	//
	r, err = os.Open(lib.DataDir() + "/in.tar." + uid)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	tr := tar.NewReader(r)
	//
	w, err = os.OpenFile(lib.DataDir()+"/out.tar."+uid, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	tw := tar.NewWriter(w)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		if header == nil {
			continue
		}
		switch header.Typeflag {
		case tar.TypeReg:
			// OCI format: layers are blobs/sha256/* files
			if _, ok := layers[header.Name]; ok {
				minifyLayer(header.Name, tr, tw, layers, includeFiles)
				lib.Logger.Println("minified layer", header.Name)
			}
		}
	}
	err = tw.Close()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	err = w.Close()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	lib.Logger.Println("finished writing out.tar")
	//
	f, err := os.OpenFile(lib.DataDir()+"/Dockerfile."+uid, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	lines, err := lib.Dockerfile(ctx, args.ContainerIn, lib.DataDir()+"/in.tar."+uid)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	lib.Logger.Println("read original dockerfile")
	//
	_, err = f.WriteString("FROM scratch\n")
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	_, err = f.WriteString(fmt.Sprintf("ADD out.tar.%s /\n", uid))
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	for _, line := range lines {
		_, err := f.WriteString(line + "\n")
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
	}
	err = f.Close()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	lib.Logger.Println("created new dockerfile")
	//
	prContext, pwContext := io.Pipe()
	go func() {
		// defer func() {}()
		tw = tar.NewWriter(pwContext)
		//
		fi, err := os.Stat(lib.DataDir() + "/out.tar." + uid)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		header, err := tar.FileInfoHeader(fi, "")
		header.Name = "out.tar." + uid
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		err = tw.WriteHeader(header)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		err = r.Close()
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		r, err = os.Open(lib.DataDir() + "/out.tar." + uid)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		_, err = io.Copy(tw, r)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		//
		fi, err = os.Stat(lib.DataDir() + "/Dockerfile." + uid)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		header, err = tar.FileInfoHeader(fi, "")
		header.Name = "Dockerfile." + uid
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		err = tw.WriteHeader(header)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		err = r.Close()
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		r, err = os.Open(lib.DataDir() + "/Dockerfile." + uid)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		_, err = io.Copy(tw, r)
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		//
		err = tw.Close()
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		err = pwContext.Close()
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		//
		err = r.Close()
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		lib.Logger.Println("finished writing context")
	}()
	//
	out, err := cli.ImageBuild(ctx, prContext, build.ImageBuildOptions{
		NoCache:    true,
		Tags:       []string{args.ContainerOut},
		Dockerfile: "Dockerfile." + uid,
		Remove:     true,
	})
	defer func() { _ = out.Body.Close() }()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	scanner := bufio.NewScanner(out.Body)
	val := make(map[string]string)
	for scanner.Scan() {
		err := json.Unmarshal(scanner.Bytes(), &val)
		if err == nil {
			lib.Logger.Println(strings.Trim(val["stream"], "\n"))
		}
	}
	err = scanner.Err()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	if val["stream"] != "Successfully tagged "+args.ContainerOut+"\n" {
		lib.Logger.Fatal("error: failed to build " + args.ContainerOut)
	}
	lib.Logger.Println("built minified image")
	//
	err = os.Remove(lib.DataDir() + "/in.tar." + uid)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	err = os.Remove(lib.DataDir() + "/out.tar." + uid)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	err = os.Remove(lib.DataDir() + "/Dockerfile." + uid)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	lib.Logger.Println("minification complete")
}

func minifyLayer(layer string, r io.Reader, tw *tar.Writer, layers map[string]int, includeFiles map[string]*lib.ScanFile) {
	layerIndex, ok := layers[layer]
	if !ok {
		panic(layer)
	}
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		if header == nil {
			continue
		}
		pth := strings.ReplaceAll("/"+header.Name, "/./", "/")
		includeFile, ok := includeFiles[pth]
		if !ok {
			continue
		}
		if includeFile.LayerIndex != layerIndex {
			continue
		}
		switch header.Typeflag {
		case tar.TypeReg:
			err := tw.WriteHeader(header)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
			_, err = io.Copy(tw, tr)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
		case tar.TypeSymlink:
			err := tw.WriteHeader(header)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
			_, err = io.Copy(tw, tr)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
		case tar.TypeDir:
			err := tw.WriteHeader(header)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
			_, err = io.Copy(tw, tr)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
		case tar.TypeLink:
			err := tw.WriteHeader(header)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
			_, err = io.Copy(tw, tr)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
		default:
			panic(fmt.Sprintf("unknown tar type: %v", header.Typeflag))
		}
	}
}
