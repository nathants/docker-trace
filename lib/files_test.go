package lib

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func md5SumFiles(bytes []byte) string {
	hash := md5.Sum(bytes)
	return hex.EncodeToString(hash[:])
}

func runStdoutStderrChanFiles(command ...string) (<-chan string, <-chan string, func(), error) {
	cmd := exec.Command(command[0], command[1:]...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stderrChan := make(chan string)
	stdoutChan := make(chan string, 1024*1024)
	tail := func(c chan<- string, r io.ReadCloser) {
		// defer func() {}()
		buf := bufio.NewReader(r)
		for {
			line, err := buf.ReadBytes('\n')
			if err != nil {
				close(c)
				return
			}
			c <- strings.TrimRight(string(line), "\n")
		}
	}
	go tail(stderrChan, stderr)
	go tail(stdoutChan, stdout)
	err = cmd.Start()
	if err != nil {
		return nil, nil, nil, err
	}
	go func() {
		// defer func() {}()
		_ = cmd.Wait()
	}()
	cancel := func() {
		_ = syscall.Kill(cmd.Process.Pid, syscall.SIGINT)
	}
	return stdoutChan, stderrChan, cancel, err
}

func runStdoutFiles(command ...string) (string, error) {
	cmd := exec.Command(command[0], command[1:]...)
	var stdout bytes.Buffer
	cmd.Stderr = os.Stderr
	cmd.Stdout = &stdout
	err := cmd.Run()
	return strings.Trim(stdout.String(), "\n"), err
}

func runFiles(command ...string) error {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

func runQuietFiles(command ...string) error {
	cmd := exec.Command(command[0], command[1:]...)
	return cmd.Run()
}

const dockerfile = `
FROM archlinux:latest
RUN pacman -Syu --noconfirm go python gcc
`

var containerFiles = fmt.Sprintf("docker-trace:test-%s", md5SumFiles([]byte(dockerfile)))

func climbGitRootFiles() {
	_, filename, _, _ := runtime.Caller(1)
	err := os.Chdir(path.Dir(filename))
	if err != nil {
		panic(err)
	}
outer:
	for {
		files, err := os.ReadDir(".")
		if err != nil {
			panic(err)
		}
		for _, file := range files {
			if file.IsDir() && file.Name() == ".git" {
				break outer
			}
			if file.Name() == "/" {
				panic("/")
			}
		}
		err = os.Chdir("..")
		if err != nil {
			panic(err)
		}
	}
}

func ensureTestContainerFiles() {
	if runQuietFiles("docker", "inspect", containerFiles) != nil {
		dir, err := os.MkdirTemp("", "docker-trace-test.")
		if err != nil {
			panic(err)
		}
		err = os.WriteFile(dir+"/Dockerfile", []byte(dockerfile), 0666)
		if err != nil {
			panic(err)
		}
		err = runFiles("docker", "build", "-t", containerFiles, "--network", "host", dir)
		if err != nil {
			panic(err)
		}
		err = os.RemoveAll(dir)
		if err != nil {
			panic(err)
		}
	}
}

func ensureDockerTraceFiles() {
	err := runFiles("go", "build", ".")
	if err != nil {
		panic(err)
	}
}

func ensureSetupFiles() {
	climbGitRootFiles()
	ensureTestContainerFiles()
	ensureDockerTraceFiles()
}

func traceCmd(dir string, command string) ([]string, error) {
	if dir == "" {
		dir = "/tmp"
	}
	stdoutChan, stderrChan, cancel, err := runStdoutStderrChanFiles("./docker-trace", "files")
	if err != nil {
		return nil, err
	}
	line := <-stderrChan
	if line != "ready" {
		return nil, fmt.Errorf("%s", line)
	}
	id, err := runStdoutFiles("docker", "run", "-d", "-t", "-v", dir+":/code", "--rm", containerFiles, "bash", "-c", command)
	if err != nil {
		return nil, err
	}
	err = runFiles("docker", "wait", id)
	if err != nil {
		return nil, err
	}
	cancel()
	var files []string
	for line := range stdoutChan {
		parts := strings.SplitN(line, " ", 2)
		fileID := parts[0]
		file := parts[1]
		if id == fileID {
			files = append(files, file)
		}
	}
	return files, nil
}

func TestTraceCat(t *testing.T) {
	ensureSetupFiles()
	files, err := traceCmd("", "cat /etc/hosts")
	if err != nil {
		t.Error(err)
		return
	}
	if !Contains(files, "/etc/hosts") {
		fmt.Println(strings.Join(files, "\n"))
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTraceCdCat(t *testing.T) {
	ensureSetupFiles()
	files, err := traceCmd("", "cd /etc && cat hosts")
	if err != nil {
		t.Error(err)
		return
	}
	if !Contains(files, "/etc/hosts") {
		fmt.Println(strings.Join(files, "\n"))
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTraceCdBashCat(t *testing.T) {
	ensureSetupFiles()
	files, err := traceCmd("", "cd /etc && bash -c \"cat hosts\"")
	if err != nil {
		t.Error(err)
		return
	}
	if !Contains(files, "/etc/hosts") {
		fmt.Println(strings.Join(files, "\n"))
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTracePythonOpen(t *testing.T) {
	ensureSetupFiles()
	files, err := traceCmd("", "python -c \"open('/etc/hosts')\"")
	if err != nil {
		t.Error(err)
		return
	}
	if !Contains(files, "/etc/hosts") {
		fmt.Println(strings.Join(files, "\n"))
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTraceBashCdPythonOpen(t *testing.T) {
	ensureSetupFiles()
	files, err := traceCmd("", "cd /etc && python -c \"open('hosts')\"")
	if err != nil {
		t.Error(err)
		return
	}
	if !Contains(files, "/etc/hosts") {
		fmt.Println(strings.Join(files, "\n"))
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTracePythonCdOpen(t *testing.T) {
	ensureSetupFiles()
	files, err := traceCmd("", "python -c \"import os; os.chdir('/etc'); open('hosts')\"")
	if err != nil {
		t.Error(err)
		return
	}
	if !Contains(files, "/etc/hosts") {
		fmt.Println(strings.Join(files, "\n"))
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTracePythonCdStat(t *testing.T) {
	ensureSetupFiles()
	files, err := traceCmd("", "python -c \"import os; os.chdir('/etc'); os.stat('hosts')\"")
	if err != nil {
		t.Error(err)
		return
	}
	if !Contains(files, "/etc/hosts") {
		fmt.Println(strings.Join(files, "\n"))
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTraceGoOpen(t *testing.T) {
	ensureSetupFiles()
	dir, err := os.MkdirTemp("", "docker-trace-test.")
	if err != nil {
		t.Error(err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	const code = `
package main
import (
    "os"
    "time"
)
func main() {
    go func() {
      _, err := os.Open("/etc/hosts")
      if err != nil {
          panic(err)
      }
      os.Exit(0)
    }()
    time.Sleep(time.Hour)
}
`
	err = os.WriteFile(dir+"/main.go", []byte(code), 0666)
	if err != nil {
		t.Error(err)
		return
	}
	files, err := traceCmd(dir, "go run /code/main.go")
	if err != nil {
		t.Error(err)
		return
	}
	if !Contains(files, "/etc/hosts") {
		fmt.Println(strings.Join(files, "\n"))
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTraceGoCdOpen(t *testing.T) {
	ensureSetupFiles()
	dir, err := os.MkdirTemp("", "docker-trace-test.")
	if err != nil {
		t.Error(err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	const code = `
package main
import (
    "os"
    "time"
)
func main() {
    go func() {
      err := os.Chdir("/etc")
      if err != nil {
          panic(err)
      }
      _, err = os.Open("hosts")
      if err != nil {
          panic(err)
      }
      os.Exit(0)
    }()
    time.Sleep(time.Hour)
}
`
	err = os.WriteFile(dir+"/main.go", []byte(code), 0666)
	if err != nil {
		t.Error(err)
		return
	}
	files, err := traceCmd(dir, "go run /code/main.go")
	if err != nil {
		t.Error(err)
		return
	}
	if !Contains(files, "/etc/hosts") {
		fmt.Println(strings.Join(files, "\n"))
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTraceGoCdStat(t *testing.T) {
	ensureSetupFiles()
	dir, err := os.MkdirTemp("", "docker-trace-test.")
	if err != nil {
		t.Error(err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	const code = `
package main
import (
    "os"
    "time"
)
func main() {
    go func() {
      err := os.Chdir("/etc")
      if err != nil {
          panic(err)
      }
      _, err = os.Stat("hosts")
      if err != nil {
          panic(err)
      }
      os.Exit(0)
    }()
    time.Sleep(time.Hour)
}
`
	err = os.WriteFile(dir+"/main.go", []byte(code), 0666)
	if err != nil {
		t.Error(err)
		return
	}
	files, err := traceCmd(dir, "go run /code/main.go")
	if err != nil {
		t.Error(err)
		return
	}
	if !Contains(files, "/etc/hosts") {
		fmt.Println(strings.Join(files, "\n"))
		t.Errorf("didnt find /etc/hosts")
		return
	}
}

func TestTraceCdFailCat(t *testing.T) {
	ensureSetupFiles()
	files, err := traceCmd("", "cd /fake; cat hosts")
	if err != nil {
		t.Error(err)
		return
	}
	if Contains(files, "/fake/hosts") {
		fmt.Println(strings.Join(files, "\n"))
		t.Errorf("found /fake/hosts")
		return
	}
	if Contains(files, "/hosts") {
		fmt.Println(strings.Join(files, "\n"))
		t.Errorf("found /hosts")
		return
	}
}
