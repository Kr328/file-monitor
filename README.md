# File Monitor for Android

A simple cli tool to monitor the file opening of application processes.

### Requirement

1. ebpf enabled kernel
2. kprobe enabled kernel
3. arm64/x86_64 architecture
4. root required

### Usage

```bash
# ./file-monitor
```

### As Library

```go
m, err := monitor.NewMonitor()
if err != nil {
	println(err.Error())
	return
}
defer m.Close()

m.Launch()

for {
	event, ok := <-m.Events(): 
	
	// handle events
}
```

### Build

1. Install `make`, `clang`, `Android NDK`
2. `ANDROID_NDK=/path/to/android-ndk make all`
