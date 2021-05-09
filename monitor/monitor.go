package monitor

import (
	"os"
	"sync"
	"syscall"

	"github/kr328/file-monitor/bpf"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

type Monitor struct {
	program  *bpf.Program
	reader   *perf.Reader
	link     link.Link
	events   chan *ResolvedEvent
	singleDo sync.Once
}

func (m *Monitor) Close() error {
	_ = m.link.Close()

	return m.program.Close()
}

func (m *Monitor) Launch() {
	m.singleDo.Do(func() {
		go func() {
			defer close(m.events)

			for {
				record, err := m.reader.Read()
				if err != nil {
					return
				}

				event, err := bpf.UnpackEvent(record.RawSample)
				if err != nil {
					continue
				}

				if event.Pid == syscall.Getpid() {
					continue
				}

				r := ResolveEvent(event)

				m.events <- r
			}
		}()
	})
}

func (m *Monitor) Events() <-chan *ResolvedEvent {
	return m.events
}

func NewMonitor() (*Monitor, error) {
	program, err := bpf.Load()
	if err != nil {
		return nil, err
	}

	filpOpen, err := link.Kprobe("do_filp_open", program.FileOpen)
	if err != nil {
		return nil, err
	}

	reader, err := perf.NewReader(program.Events, os.Getpagesize())
	if err != nil {
		return nil, err
	}

	return &Monitor{
		program:  program,
		reader:   reader,
		link:     filpOpen,
		events:   make(chan *ResolvedEvent, 64),
		singleDo: sync.Once{},
	}, nil
}
