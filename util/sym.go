package util

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
)

func ResolveSyscallSymbols(calls []string) (map[string]string, error) {
	prefix := ""

	machine := ResolveMachineArch()

	switch machine {
	case "x86_64":
		prefix = "__x64_sys_"
	case "aarch64":
		prefix = "__arm64_sys_"
	default:
		return nil, errors.New("unsupported platform " + machine)
	}

	callsMap := map[string]string{}

	for _, call := range calls {
		callsMap[prefix+call] = call
	}

	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := map[string]string{}

	reader := bufio.NewReader(file)

	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}

			return nil, err
		}

		fields := strings.Fields(string(line))
		if len(fields) < 3 {
			continue
		}

		if !strings.EqualFold(fields[1], "t") {
			continue
		}

		if call, ok := callsMap[fields[2]]; ok {
			result[call] = fields[2]
		}
	}

	return result, nil
}
