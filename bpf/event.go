package bpf

import (
	"encoding/binary"
	"io"
	"unsafe"

	"file-monitor/util"
)

type Event struct {
	Pid         int
	Uid         int
	DirectoryFd int
	ThreadName  string
	Path        string
}

var nativeEndian binary.ByteOrder

// from https://github.com/vishvananda/netlink/blob/bca67dfc8220b44ef582c9da4e9172bf1c9ec973/nl/nl_linux.go#L52-L62
func init() {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		nativeEndian = binary.BigEndian
	} else {
		nativeEndian = binary.LittleEndian
	}
}

func UnpackEvent(raw []byte) (*Event, error) {
	if len(raw) < 24 {
		return nil, io.ErrShortBuffer
	}

	r := &Event{
		Pid:         int(nativeEndian.Uint32(raw[0:4])),
		Uid:         int(nativeEndian.Uint32(raw[4:8])),
		DirectoryFd: int(nativeEndian.Uint32(raw[8:12])),
		ThreadName:  util.ParseNulString(raw[12:28]),
		Path:        util.ParseNulString(raw[28:]),
	}

	return r, nil
}
