package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"file-monitor/bpf"
	"file-monitor/util"
)

type ResolvedEvent struct {
	Cmdline string
	Path    string
	Action  bpf.Action
	Uid     int
	Pid     int
}

func ResolveEvent(event *bpf.Event) *ResolvedEvent {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", event.Pid)
	cwdPath := fmt.Sprintf("/proc/%d/cwd", event.Pid)
	directoryPath := fmt.Sprintf("/proc/%d/fd/%d", event.Pid, event.DirectoryFd)

	cmdline := event.ThreadName
	path := event.Path

	if bs, err := ioutil.ReadFile(cmdlinePath); err == nil {
		if c := util.ParseNulString(bs); c != "" {
			cmdline = c
		}
	}

	if path[0] != '/' {
		if event.DirectoryFd >= 0 {
			if bs, err := ioutil.ReadFile(directoryPath); err == nil {
				if c := util.ParseNulString(bs); c != "" {
					path = c + "/" + path
				}
			}
		} else if pwd, err := os.Readlink(cwdPath); err == nil {
			path = pwd + "/" + path
		}
	}

	return &ResolvedEvent{
		Cmdline: cmdline,
		Path:    path,
		Action:  event.Action,
		Uid:     event.Uid,
		Pid:     event.Pid,
	}
}
