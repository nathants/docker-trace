package lib

import (
    "bufio"
    "bytes"
    "context"
    "crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
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
		containerID := parts[0]
		file := parts[1]
		// Only process files from actual containers (not empty container ID)
		if containerID == "" || containerID == "0" {
			continue
		}
		// Skip already seen files
		if seen[file] {
			continue
		}
		// Filter out host system paths and Docker internals
		if strings.HasPrefix(file, "/proc/") || 
		   strings.HasPrefix(file, "/sys/") || 
		   strings.HasPrefix(file, "/dev/") ||
		   strings.Contains(file, "/overlay2/") ||
		   strings.Contains(file, "/merged") ||
		   strings.HasPrefix(file, "/var/lib/docker/") ||
		   file == "/" ||
		   file == "/proc" ||
		   file == "/sys" ||
		   file == "/dev" ||
		   !strings.HasPrefix(file, "/") {
			continue
		}
		// Only include regular container paths
		files = append(files, file)
		seen[file] = true
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
		containerID := parts[0]
		file := parts[1]
		// Only process files from actual containers (not empty container ID)
		if containerID == "" || containerID == "0" {
			continue
		}
		// Skip already seen files
		if seen[file] {
			continue
		}
		// Filter out host system paths and Docker internals
		if strings.HasPrefix(file, "/proc/") || 
		   strings.HasPrefix(file, "/sys/") || 
		   strings.HasPrefix(file, "/dev/") ||
		   strings.Contains(file, "/overlay2/") ||
		   strings.Contains(file, "/merged") ||
		   strings.HasPrefix(file, "/var/lib/docker/") ||
		   file == "/" ||
		   file == "/proc" ||
		   file == "/sys" ||
		   file == "/dev" ||
		   !strings.HasPrefix(file, "/") {
			continue
		}
		// Only include regular container paths
		files = append(files, file)
		seen[file] = true
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

// Verifies that including a single file like /etc/hosts does not cause all of
// its parent directory's children (e.g. other files in /etc) to be included.
// Ensures including /etc/hosts does not include other files under /etc.
func TestMinifyNoParentDirExplosion(t *testing.T) {
    climbGitRootMinify()
    ensureDockerTraceMinify()

    df := `
FROM debian:latest
RUN bash -lc 'echo secret > /etc/nonce_file'
CMD ["bash","-lc","cat /etc/hosts >/dev/null && sleep 1"]
`
    tag := fmt.Sprintf("docker-trace:minify-parentdir-%s", md5SumMinify([]byte(df)))
    if runQuietMinify("docker", "inspect", tag) != nil {
        dir, err := os.MkdirTemp("", "docker-trace-minify-parent.")
        if err != nil {
            t.Fatal(err)
        }
        defer func() { _ = os.RemoveAll(dir) }()
        if err := os.WriteFile(path.Join(dir, "Dockerfile"), []byte(df), 0666); err != nil {
            t.Fatal(err)
        }
        if err := runMinify("docker", "build", "-t", tag, "--network", "host", dir); err != nil {
            t.Fatal(err)
        }
    }

    includes := []string{"/etc/hosts"}
    out := tag + "-min"
    if err := runStdinMinify(strings.Join(includes, "\n"), "./docker-trace", "minify", tag, out); err != nil {
        t.Fatal(err)
    }

    ctx := context.Background()
    files, _, err := Scan(ctx, out, "", false)
    if err != nil {
        t.Fatal(err)
    }
    hasHosts := false
    hasNonce := false
    for _, f := range files {
        if f.Path == "/etc/hosts" {
            hasHosts = true
        }
        if f.Path == "/etc/nonce_file" {
            hasNonce = true
        }
    }
    if !hasHosts {
        t.Fatalf("expected /etc/hosts present in minified image")
    }
    if hasNonce {
        t.Fatalf("unexpected /etc/nonce_file present in minified image")
    }
}
