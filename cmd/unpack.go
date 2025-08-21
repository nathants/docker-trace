package dockertrace

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"

	"github.com/alexflint/go-arg"
	"github.com/nathants/docker-trace/lib"
)

func init() {
	lib.Commands["unpack"] = unpack
	lib.Args["unpack"] = unpackArgs{}
}

type unpackArgs struct {
	Name     string `arg:"positional,required"`
	NoRename bool   `arg:"-r,--no-rename" default:"false"`
	NoUntar  bool   `arg:"-u,--no-untar" default:"false"`
}

func (unpackArgs) Description() string {
	return "\nunpack a container into directories and files\n"
}

func unpack() {
	var args unpackArgs
	arg.MustParse(&args)

	shell := fmt.Sprintf("set -eou pipefail; docker save %s | tar xf -", args.Name)
	cmd := exec.Command("bash", "-c", shell)
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		lib.Logger.Fatal("error:", shell, err)
	}

	bytes, err := os.ReadFile("manifest.json")
	if err != nil {
		lib.Logger.Fatal("error:", err)
	}

	var manifests []lib.Manifest

	err = json.Unmarshal(bytes, &manifests)
	if err != nil {
		lib.Logger.Fatal("error:", err)
	}

	manifest, err := lib.FindManifest(manifests, args.Name)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}

	layerNames := make(map[string]string)
	for i, layerBlob := range manifest.Layers {
		layerNames[layerBlob] = fmt.Sprintf("layer%02d", i)
	}

	if !args.NoRename {
		for _, layerBlob := range manifest.Layers {
			err := moveAndRenameBlob(layerBlob, layerNames)
			if err != nil {
				lib.Logger.Fatal("error:", err)
			}
		}
	}

	if !args.NoUntar {
		for _, layerBlob := range manifest.Layers {
			err := untarLayer(args.NoRename, layerBlob, layerNames)
			if err != nil {
				lib.Logger.Fatal("error:", err)
			}
		}
	}

	if !args.NoUntar {
		for _, layerBlob := range manifest.Layers {
			err := deleteLayerTarball(args.NoRename, layerBlob, layerNames)
			if err != nil {
				lib.Logger.Fatal("error:", err)
			}
		}
	}

	if !args.NoRename {
		_ = os.RemoveAll("blobs")
	}

}

func deleteLayerTarball(noRename bool, layerBlob string, layerNames map[string]string) error {
	layerName := layerBlob
	if !noRename {
		var ok bool
		layerName, ok = layerNames[layerBlob]
		if !ok {
			return fmt.Errorf("error: %s %v", layerBlob, layerNames)
		}
		layerName = layerName + ".tar"
	}
	err := os.Remove(layerName)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func untarLayer(noRename bool, layerBlob string, layerNames map[string]string) error {
	tarFile := layerBlob
	layerDir := path.Base(layerBlob)
	if !noRename {
		var ok bool
		layerDir, ok = layerNames[layerBlob]
		if !ok {
			return fmt.Errorf("no layer match: %s %v", layerBlob, layerNames)
		}
		tarFile = layerDir + ".tar"
	}

	err := os.MkdirAll(layerDir, 0755)
	if err != nil {
		return fmt.Errorf("mkdir failure: %w %s", err, layerDir)
	}

	cmd := exec.Command("tar", "--delay-directory-restore", "-xf", "../"+tarFile)
	cmd.Dir = layerDir
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("tar expansion failure: %w %s", err, layerDir)
	}
	return nil
}

func moveAndRenameBlob(layerBlob string, layerNames map[string]string) error {
	layerName, ok := layerNames[layerBlob]
	if !ok {
		return fmt.Errorf("error: %s %v", layerBlob, layerNames)
	}
	newName := layerName + ".tar"

	source, err := os.Open(layerBlob)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()

	dest, err := os.Create(newName)
	if err != nil {
		return err
	}
	defer func() { _ = dest.Close() }()

	_, err = io.Copy(dest, source)
	if err != nil {
		return err
	}

	_ = source.Close()
	err = os.Remove(layerBlob)
	if err != nil {
		return err
	}

	return nil
}
