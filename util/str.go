package util

import (
	"bytes"
	"strings"
)

func ParseNulString(buf []byte) string {
	nulIndex := bytes.IndexByte(buf, 0)
	if nulIndex < 0 {
		return string(buf)
	}

	return string(buf[:nulIndex])
}

func ParseNulStringInt8(buf []int8) string {
	sb := &strings.Builder{}

	for _, value := range buf {
		if value == 0 {
			break
		}

		sb.WriteByte(byte(value))
	}

	return sb.String()
}
