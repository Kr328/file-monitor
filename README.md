# File Monitor for Android

A simple cli tool to monitor the file opening of application processes.

### Requirement

1. ebpf enabled kernel
   ```bash
   # zcat /proc/config.gz | grep CONFIG_BPF=y
   CONFIG_BPF=y
   ```
2. kprobe enabled kernel
   ```bash
   # zcat /proc/config.gz | grep CONFIG_KPROBES=y
   CONFIG_KPROBES=y
   ```
3. arm64/x86_64 architecture
   ```bash
   $ uname -m
   aarch64 or x86_64
   ```
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

### Notice

##### 3rd party licenses

1. **bpf_core_read.h**
   LGPL-2.1 OR BSD-2-Clause