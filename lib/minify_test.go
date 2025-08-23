package lib

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func md5SumMinify(bytes []byte) string {
	hash := md5.Sum(bytes)
	return hex.EncodeToString(hash[:])
}

func runStdinMinify(stdin string, command ...string) error {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = bytes.NewBufferString(stdin + "\n")
	return cmd.Run()
}

func runStdoutMinify(command ...string) (string, error) {
	cmd := exec.Command(command[0], command[1:]...)
	var stdout bytes.Buffer
	cmd.Stderr = os.Stderr
	cmd.Stdout = &stdout
	err := cmd.Run()
	return strings.Trim(stdout.String(), "\n"), err
}

func runStdoutStderrChanMinify(command ...string) (<-chan string, <-chan string, func(), error) {
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

func runMinify(command ...string) error {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}

func runQuietMinify(command ...string) error {
	cmd := exec.Command(command[0], command[1:]...)
	return cmd.Run()
}

func climbGitRootMinify() {
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

func ensureDockerTraceMinify() {
	err := runMinify("go", "build", ".")
	if err != nil {
		panic(err)
	}
}

func ensureTestContainerMinify(app, kind string) string {
	stdout, err := runStdoutMinify("bash", "-c", fmt.Sprintf("cat examples/%s/*", app))
	if err != nil {
		panic(err)
	}
	hash := md5SumMinify([]byte(stdout))
	container := fmt.Sprintf("docker-trace:minify-%s-%s-%s", app, kind, hash)
	if runQuietMinify("docker", "inspect", container) != nil {
		err = runMinify("docker", "build", "-t", container, "--network", "host", "-f", "examples/"+app+"/Dockerfile."+kind, "examples/"+app)
		if err != nil {
			panic(err)
		}
	}
	return container
}

func ensureSetupMinify(app, kind string) string {
	_ = runQuietMinify("bash", "-c", "docker kill $(docker ps -q)")
	climbGitRootMinify()
	ensureDockerTraceMinify()
	container := ensureTestContainerMinify(app, kind)
	return container
}

func testWeb(t *testing.T, app, kind string) {
	container := ensureSetupMinify(app, kind)
	fmt.Println("start trace container")
	stdoutChan, stderrChan, cancel, err := runStdoutStderrChanMinify("./docker-trace", "files")
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("wait for trace container ready")
	line := <-stderrChan
	if line != "ready" {
		t.Error(line)
		return
	}
	fmt.Println("trace container ready, start test container")
	// Clear the channel of any existing events before starting container
	drainChannel := func(ch <-chan string) {
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
	drainChannel(stdoutChan)
	//
	id, err := runStdoutMinify("docker", "run", "-d", "-t", "--rm", "--network", "host", container)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println("Container ID:", id)
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		IdleConnTimeout:     1 * time.Second,
		TLSHandshakeTimeout: 1 * time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   1 * time.Second,
	}
	//
	start := time.Now()
	for {
		if time.Since(start) > 10*time.Second {
			t.Error("timeout")
			return
		}
		out, err := client.Get("https://localhost:8080/hello/xyz")
		if err == nil {
			bytes, _ := io.ReadAll(out.Body)
			_ = out.Body.Close()
			fmt.Println(out.StatusCode, string(bytes))
			break
		}
		fmt.Println(err)
		time.Sleep(1 * time.Second)
	}
	fmt.Println("test passed, kill test container")
	//
	err = runMinify("docker", "kill", id)
	if err != nil {
		t.Error(err)
		return
	}
	//
	fmt.Println("cancel trace container and drain output")
	cancel()
	var files []string
	seen := make(map[string]bool)
	for line := range stdoutChan {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		file := parts[1]
		// Filter out noise and duplicates
		if !seen[file] && !strings.HasPrefix(file, "/proc/") && !strings.HasPrefix(file, "/sys/") && !strings.HasPrefix(file, "/dev/") {
			// Also filter out paths that are clearly from the host system, not the container
			if !strings.Contains(file, "/overlay2/") && !strings.HasPrefix(file, "/var/lib/docker/") {
				files = append(files, file)
				seen[file] = true
			}
		}
	}
	fmt.Printf("Collected %d unique files from trace\n", len(files))
	//
	fmt.Println("check that test container is not reachable")
	out, err := client.Get("https://localhost:8080/hello/xyz")
	if err == nil {
		_ = out.Body.Close()
		t.Error("server should have been killed")
		return
	}
	//
	fmt.Println("start minification")
	fmt.Println("Files being passed to minify:")
	for _, f := range files {
		fmt.Println("  ", f)
	}
	err = runStdinMinify(strings.Join(files, "\n"), "./docker-trace", "minify", container, container+"-min")
	if err != nil {
		t.Error(err)
		return
	}
	//
	fmt.Println("start minified container")
	id, err = runStdoutMinify("docker", "run", "-d", "--network", "host", "--rm", container+"-min")
	if err != nil {
		t.Error(err)
		return
	}
	//
	start = time.Now()
	for {
		if time.Since(start) > 5*time.Second {
			t.Error("timeout")
			return
		}
		out, err := client.Get("https://localhost:8080/hello/xyz")
		if err == nil {
			bytes, _ := io.ReadAll(out.Body)
			_ = out.Body.Close()
			fmt.Println(out.StatusCode, string(bytes))
			break
		}
		fmt.Println(err)
		time.Sleep(1 * time.Second)
	}
	fmt.Println("compare image sizes")
	//
	stdout, err := runStdoutMinify("docker", "inspect", container, "-f", "{{.Size}}")
	if err != nil {
		t.Error(err)
		return
	}
	size := Atoi(stdout)
	//
	stdout, err = runStdoutMinify("docker", "inspect", container+"-min", "-f", "{{.Size}}")
	if err != nil {
		t.Error(err)
		return
	}
	sizeMin := Atoi(stdout)
	if !(sizeMin < size) {
		t.Error("not smaller")
		return
	}
	err = runMinify("docker", "kill", id)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestGoWebArch(t *testing.T) {
	testWeb(t, "go-web", "arch")
}

func TestGoWebAlpine(t *testing.T) {
	testWeb(t, "go-web", "alpine")
}

func TestGoWebDebian(t *testing.T) {
	testWeb(t, "go-web", "debian")
}

func TestGoWebUbuntu(t *testing.T) {
	testWeb(t, "go-web", "ubuntu")
}

func TestNodeWebArch(t *testing.T) {
	testWeb(t, "node-web", "arch")
}

func TestNodeWebAlpine(t *testing.T) {
	testWeb(t, "node-web", "alpine")
}

func TestNodeWebDebian(t *testing.T) {
	testWeb(t, "node-web", "debian")
}

func TestNodeWebUbuntu(t *testing.T) {
	testWeb(t, "node-web", "ubuntu")
}

func TestSymlinkClosureDebian(t *testing.T) {
	climbGitRootMinify()
	ensureDockerTraceMinify()
	dockerfile := `
FROM debian:latest
RUN ln -s /etc/hosts /hosts_link
CMD ["bash","-lc","cat /hosts_link && sleep 1"]
`
	hash := md5SumMinify([]byte(dockerfile))
	container := fmt.Sprintf("docker-trace:minify-symlink-debian-%s", hash)
	if runQuietMinify("docker", "inspect", container) != nil {
		dir, err := os.MkdirTemp("", "docker-trace-test.")
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = os.RemoveAll(dir) }()
		err = os.WriteFile(path.Join(dir, "Dockerfile"), []byte(dockerfile), 0666)
		if err != nil {
			t.Error(err)
			return
		}
		err = runMinify("docker", "build", "-t", container, "--network", "host", dir)
		if err != nil {
			t.Error(err)
			return
		}
	}
	stdoutChan, stderrChan, cancel, err := runStdoutStderrChanMinify("./docker-trace", "files")
	if err != nil {
		t.Error(err)
		return
	}
	line := <-stderrChan
	if line != "ready" {
		t.Error(line)
		return
	}
	drain := func(ch <-chan string) {
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
	drain(stdoutChan)
	_, err = runStdoutMinify("docker", "run", "--rm", "--network", "host", container)
	if err != nil {
		t.Error(err)
		return
	}
	cancel()
	var files []string
	seen := make(map[string]bool)
	for line := range stdoutChan {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		file := parts[1]
		if !seen[file] && !strings.HasPrefix(file, "/proc/") && !strings.HasPrefix(file, "/sys/") && !strings.HasPrefix(file, "/dev/") {
			if !strings.Contains(file, "/overlay2/") && !strings.HasPrefix(file, "/var/lib/docker/") {
				files = append(files, file)
				seen[file] = true
			}
		}
	}
	if !Contains(files, "/hosts_link") {
		t.Errorf("did not trace /hosts_link: %v", files)
		return
	}
	err = runStdinMinify(strings.Join(files, "\n"), "./docker-trace", "minify", container, container+"-min")
	if err != nil {
		t.Error(err)
		return
	}
	err = runMinify("docker", "run", "--rm", container+"-min", "bash", "-lc", "cat /hosts_link >/dev/null")
	if err != nil {
		t.Error(err)
		return
	}
}

func TestFilesHandleLineOpenatDirfd(t *testing.T) {
	dfd, err := os.Open("/etc")
	if err != nil {
		t.Fatalf("open /etc: %v", err)
	}
	defer func() { _ = dfd.Close() }()

	pid := os.Getpid()
	cwds := map[string]string{}
	cgroups := map[string]string{"cg1": "container1"}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() {
		_ = r.Close()
		_ = w.Close()
	}()

	oldStdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	line := fmt.Sprintf(
		"openat\tcg1\t%d\t0\tproc\t0\thosts\t%d",
		pid, dfd.Fd(),
	)
	FilesHandleLine(cwds, cgroups, line)

	_ = w.Close()
	scanner := bufio.NewScanner(r)
	found := false
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "container1 /etc/hosts" {
			found = true
			break
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan stdout: %v", err)
	}
	if !found {
		t.Fatalf("expected 'container1 /etc/hosts' not found")
	}
}

func md5Hex(xs ...string) string {
	h := md5.New()
	for _, x := range xs {
		_, _ = h.Write([]byte(x))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func buildCOpenatImage(t *testing.T) string {
	csrc := `#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
int main() {
  int dfd = open("/etc", O_RDONLY | O_DIRECTORY);
  if (dfd < 0) { perror("open"); return 1; }
  int fd = openat(dfd, "hosts", O_RDONLY);
  if (fd < 0) { perror("openat"); return 1; }
  char buf[1];
  (void)read(fd, buf, 1);
  close(fd);
  close(dfd);
  return 0;
}
`
	df := fmt.Sprintf(`FROM %s
COPY main.c /usr/local/src/main.c
RUN cc /usr/local/src/main.c -o /usr/local/bin/openat_example
`, containerFiles)
	tag := fmt.Sprintf("docker-trace:c-openat-%s", md5Hex(df, csrc))
	if runQuietFiles("docker", "inspect", tag) == nil {
		return tag
	}
	dir, err := os.MkdirTemp("", "docker-trace-c-openat.")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(df), 0666); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.c"), []byte(csrc), 0666); err != nil {
		t.Fatalf("write main.c: %v", err)
	}
	if err := runFiles("docker", "build", "-t", tag, "--network", "host", dir); err != nil {
		t.Fatalf("docker build: %v", err)
	}
	return tag
}

func TestTraceCOpenatDirfdDockerBuild(t *testing.T) {
	ensureSetupFiles()

	image := buildCOpenatImage(t)

	stdoutChan, stderrChan, cancel, err := runStdoutStderrChanFiles("./docker-trace", "files")
	if err != nil {
		t.Fatalf("start tracer: %v", err)
	}
	line := <-stderrChan
	if line != "ready" {
		t.Fatalf("unexpected tracer line: %s", line)
	}

	// drain prior events
	drain := func(ch <-chan string) {
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
	drain(stdoutChan)

	id, err := runStdoutFiles("docker", "run", "-d", "-t", "--rm", image, "/usr/local/bin/openat_example")
	if err != nil {
		cancel()
		t.Fatalf("docker run: %v", err)
	}
	if err := runFiles("docker", "wait", id); err != nil {
		cancel()
		t.Fatalf("docker wait: %v", err)
	}

	cancel()
	found := false
	for s := range stdoutChan {
		if strings.Contains(s, " /etc/hosts") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("did not capture /etc/hosts via openat(dirfd)")
	}
}
