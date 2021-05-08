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
	Uid     int
	Pid     int
}

func ResolveEvent(event *bpf.Event) *ResolvedEvent {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", event.Pid)
	cwdPath := fmt.Sprintf("/proc/%d/cwd", event.Pid)

	cmdline := event.ThreadName
	path := event.Path

	if bs, err := ioutil.ReadFile(cmdlinePath); err == nil {
		cmdline = util.ParseNulString(bs)
	}

	if path[0] != '/' {
		if pwd, err := os.Readlink(cwdPath); err == nil {
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
