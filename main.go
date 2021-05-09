package main

import (
	"log"
	"os"
	"syscall"

	"file-monitor/bpf"
	"file-monitor/util"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

func main() {
	program, err := bpf.Load()
	if err != nil {
		panic(err.Error())
	}
	defer program.Close()

	calls := []string{
		"open",
		"openat",
		"openat2",
		"mkdir",
		"mkdirat",
		"unlink",
		"unlinkat",
	}

	symbols, err := util.ResolveSyscallSymbols(calls)
	if err != nil {
		panic(err.Error())
	} else if len(symbols) == 0 {
		panic("syscall symbols unavailable")
	}

	returnFilename, err := link.Kretprobe("getname_flags", program.ReturnFilename)
	if err != nil {
		panic(err.Error())
	}
	defer returnFilename.Close()

	var links []link.Link
	defer func() {
		for _, symLink := range links {
			_ = symLink.Close()
		}
	}()

	for call, symbol := range symbols {
		var symLink link.Link
		var err error

		switch call {
		case "open":
			symLink, err = link.Kprobe(symbol, program.Open)
		case "openat":
			symLink, err = link.Kprobe(symbol, program.OpenAt)
		case "openat2":
			symLink, err = link.Kprobe(symbol, program.OpenAt2)
		case "mkdir":
			symLink, err = link.Kprobe(symbol, program.Mkdir)
		case "mkdirat":
			symLink, err = link.Kprobe(symbol, program.MkdirAt)
		case "unlink":
			symLink, err = link.Kprobe(symbol, program.Unlink)
		case "unlinkat":
			symLink, err = link.Kprobe(symbol, program.UnlinkAt)
		}
		if err != nil {
			panic(err.Error())
		}

		links = append(links, symLink)

		println("Hook " + symbol + " as " + call)
	}

	reader, err := perf.NewReader(program.Events, os.Getpagesize())
	if err != nil {
		panic(err.Error())
	}
	defer reader.Close()

	for {
		record, err := reader.Read()
		if err != nil {
			println(err.Error())

			return
		}

		event, err := bpf.UnpackEvent(record.RawSample)
		if err != nil {
			log.Printf("Invalid record: %s, len = %d\n", err.Error(), len(record.RawSample))

			continue
		}

		if event.Pid == syscall.Getpid() {
			continue
		}

		r := ResolveEvent(event)

		log.Printf("action=%s pid=%d uid=%d cmdline=%s path=%s", r.Action.String(), r.Pid, r.Uid, r.Cmdline, r.Path)
	}
}
