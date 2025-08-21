package dockertrace

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/nathants/docker-trace/lib"
)

func init() {
	lib.Commands["files"] = files
	lib.Args["files"] = filesArgs{}
}

type filesArgs struct {
	BpfRingBufferPages int `arg:"-p,--rb-pages" default:"65536" help:"double this value if you encounter 'Lost events' messages on stderr"`
}

func (filesArgs) Description() string {
	return "\nbpftrace filesystem access in a running container\n"
}

const filesBpftraceFilterTID = `/@filename[tid] != 0/`

const filesBpftrace = `#!/usr/bin/env bpftrace

#include <linux/sched.h>

// Track docker container creation via cgroup - format: syscall, cgroup, pid, ppid, comm, errno, path
tracepoint:cgroup:cgroup_mkdir { 
    printf("cgroup_mkdir\t%llu\t0\t0\t-\t0\t%s\n", args->id, str(args->path)); 
}

// Track exec calls directly without storing in map
tracepoint:syscalls:sys_enter_exec* { 
    $fn = str(args->filename);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        printf("exec\t%llu\t%d\t%d\t%s\t0\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $fn); 
    }
}

// Store filenames from sys_enter for later use in sys_exit
tracepoint:syscalls:sys_enter_creat,
tracepoint:syscalls:sys_enter_statfs,
tracepoint:syscalls:sys_enter_readlinkat { 
    @filename[tid] = args->pathname; 
}

tracepoint:syscalls:sys_enter_readlink,
tracepoint:syscalls:sys_enter_truncate { 
    @filename[tid] = args->path; 
}

tracepoint:syscalls:sys_enter_utimensat,
tracepoint:syscalls:sys_enter_chdir,
tracepoint:syscalls:sys_enter_open,
tracepoint:syscalls:sys_enter_futimesat,
tracepoint:syscalls:sys_enter_access,
tracepoint:syscalls:sys_enter_openat,
tracepoint:syscalls:sys_enter_statx,
tracepoint:syscalls:sys_enter_mknod,
tracepoint:syscalls:sys_enter_mknodat,
tracepoint:syscalls:sys_enter_faccessat,
tracepoint:syscalls:sys_enter_utime,
tracepoint:syscalls:sys_enter_utimes,
tracepoint:syscalls:sys_enter_newstat,
tracepoint:syscalls:sys_enter_newlstat { 
    @filename[tid] = args->filename; 
}

// Handle sys_exit events - FILTER_TID checks map existence, then filter paths inside the block
tracepoint:syscalls:sys_exit_utimensat  FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("utimensat\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_faccessat  FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("faccessat\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_chdir      FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("chdir\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_access     FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("access\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_futimesat  FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("futimesat\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_open       FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("open\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_openat     FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("openat\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_readlink   FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("readlink\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_truncate   FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("truncate\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_readlinkat FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("readlinkat\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_statfs     FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("statfs\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_creat      FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("creat\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_statx      FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("statx\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_newstat    FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("newstat\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_mknod      FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("mknod\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_mknodat    FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("mknodat\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_utimes     FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("utimes\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}
tracepoint:syscalls:sys_exit_newlstat   FILTER_TID { 
    $fn = str(@filename[tid]);
    if (strncmp("/proc/", $fn, 6) != 0 && strncmp("/sys/", $fn, 5) != 0 && strncmp("/dev/", $fn, 5) != 0) {
        $ret = args->ret; 
        $errno = $ret >= 0 ? 0 : - $ret; 
        printf("newlstat\t%llu\t%d\t%d\t%s\t%d\t%s\n", cgroup, pid, ((struct task_struct *)curtask)->real_parent->pid, comm, $errno, $fn); 
    }
    delete(@filename[tid]); 
}

END { clear(@filename); }

`

func filesUpdateFilters() string {
	filters := filesBpftrace
	filters = strings.ReplaceAll(filters, "FILTER_TID", filesBpftraceFilterTID)
	return filters
}

func files() {
	var args filesArgs
	arg.MustParse(&args)
	//
	if exec.Command("bash", "-c", "mount | grep cgroup2").Run() != nil {
		lib.Logger.Println("fatal: cgroups v2 are required")
		lib.Logger.Println("https://wiki.archlinux.org/index.php/cgroups#Switching_to_cgroups_v2")
		lib.Logger.Println("https://wiki.archlinux.org/index.php/Kernel_parameters#GRUB")
		lib.Logger.Fatal("")
	}
	//
	//
	tempDir, err := os.MkdirTemp("", "docker-trace")
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	// filter out events from cgroups created before this process started and from filepaths in /proc/, /sys/, /dev/
	err = os.WriteFile(tempDir+"/files.bt", []byte(filesUpdateFilters()), 0666)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	ctx, cancel := context.WithCancel(context.Background())
	//
	cleanup := func() {
		_ = os.RemoveAll(tempDir)
		cancel()
	}
	lib.SignalHandler(cleanup)
	//
	env := "BPFTRACE_STRLEN=200 BPFTRACE_MAP_KEYS_MAX=8192 BPFTRACE_PERF_RB_PAGES=" + fmt.Sprint(args.BpfRingBufferPages)
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", "bash", "-c", env+" bpftrace "+tempDir+"/files.bt")
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	go func() {
		// defer func() {}()
		err := cmd.Run()
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
	}()
	//
	buf := bufio.NewReader(stdout)
	line, err := buf.ReadBytes('\n')
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	if !(strings.HasPrefix(string(line), "Attaching ") && strings.HasSuffix(string(line), " probes...\n")) {
		lib.Logger.Fatalf("error: unexected startup log: %s", string(line))
	}
	fmt.Fprintln(os.Stderr, "ready")
	//
	cwds := make(map[string]string)
	cgroups := make(map[string]string)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line, err := buf.ReadString('\n')
		if err != nil {
			cleanup()
			if err == io.EOF || err == context.Canceled {
				return
			}
			lib.Logger.Fatal("error:", err)
		}
		line = strings.TrimRight(line, "\n")
		lib.FilesHandleLine(cwds, cgroups, line)
	}
}
