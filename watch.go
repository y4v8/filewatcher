package filewatcher

import (
	"syscall"
	"github.com/y4v8/errors"
	"strings"
)

type action uint32

const (
	actionAdd    action = iota
	actionRemove
)

type watchAction struct {
	action action
	path   string
}

type watches map[string]*watch

type watch struct {
	volume     uint32
	volumeName string
	path       string
}

func newWatch(path string) (*watch, error) {
	pathUTF16, err := syscall.UTF16FromString(path)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	h, err := syscall.CreateFile(&pathUTF16[0],
		0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0)
	if err != nil {
		return nil, errors.Wrap(err)
	}
	defer syscall.CloseHandle(h)

	var fi syscall.ByHandleFileInformation
	if err = syscall.GetFileInformationByHandle(h, &fi); err != nil {
		return nil, errors.Wrap(err)
	}

	volumeName, err := getVolumePathName(path)
	if err != nil {
		return nil, errors.Wrap(err)
	}
	volumeName = volumeName[:len(volumeName)-1]

	path = path[len(volumeName):]

	w := &watch{
		volume:     fi.VolumeSerialNumber,
		volumeName: strings.ToLower(volumeName),
		path:       strings.ToLower(path),
	}

	return w, nil
}
