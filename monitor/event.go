package monitor

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github/kr328/file-monitor/bpf"
)

type ResolvedEvent struct {
	Cmdline string
	Path    string
	Uid     int
	Pid     int
}

func ResolveEvent(event *bpf.Event) *ResolvedEvent {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", event.Pid)
	cwdPath := fmt.Sprintf("/proc/%d/cwd", event.Pid)
	directoryPath := fmt.Sprintf("/proc/%d/fd/%d", event.Pid, event.DirectoryFd)

	cmdline := event.ThreadName
	path := event.Path

	if bs, err := os.ReadFile(cmdlinePath); err == nil {
		if c := unix.ByteSliceToString(bs); c != "" {
			cmdline = c
		}
	}

	if path[0] != '/' {
		if event.DirectoryFd >= 0 {
			if d, err := os.Readlink(directoryPath); err == nil {
				path = d + "/" + path
			}
		} else if pwd, err := os.Readlink(cwdPath); err == nil {
			path = pwd + "/" + path
		}
	}

	return &ResolvedEvent{
		Cmdline: cmdline,
		Path:    path,
		Uid:     event.Uid,
		Pid:     event.Pid,
	}
}
