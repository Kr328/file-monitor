package util

import (
	"strings"
	"syscall"
)

func ResolveMachineArch() string {
	u := syscall.Utsname{}
	if err := syscall.Uname(&u); err != nil {
		return ""
	}

	sb := strings.Builder{}

	for _, v := range u.Machine {
		if v == 0 {
			break
		}

		sb.WriteByte(byte(v))
	}

	return sb.String()
}
