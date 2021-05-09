package main

import (
	"fmt"
	"os"
	"os/signal"

	"github/kr328/file-monitor/monitor"
)

func main() {
	m, err := monitor.NewMonitor()
	if err != nil {
		println(err.Error())

		return
	}
	defer m.Close()

	m.Launch()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, os.Kill)

	for {
		select {
		case e, ok := <-m.Events():
			if ok {
				fmt.Printf("pid=%d uid=%d cmdline=%s path=%s\n", e.Pid, e.Uid, e.Cmdline, e.Path)
			} else {
				println("Closed")

				return
			}
		case <-signals:
			println("Exiting")
			return
		}
	}
}
