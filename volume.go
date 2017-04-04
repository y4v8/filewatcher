package filewatcher

import (
	"github.com/y4v8/errors"
	"github.com/y4v8/filewatcher/win"
	"syscall"
)

const (
	systemBufferSize uint32 = 64 * 1024
)

type volumes map[uint32]*volume

type volume struct {
	ov      syscall.Overlapped
	handle  syscall.Handle
	watches watches
	urd     win.READ_USN_JOURNAL_DATA_V1
	buffer  []byte
}

func newVolume(path string, mask win.UsnReason) (*volume, error) {
	hVolume, err := openVolume(path)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	ujd, err := win.GetUsnJournalData(hVolume)
	if err != nil {
		syscall.CloseHandle(hVolume)
		return nil, errors.Wrap(err)
	}

	v := volume{
		handle: hVolume,
		urd: win.READ_USN_JOURNAL_DATA_V1{
			READ_USN_JOURNAL_DATA_V0: win.READ_USN_JOURNAL_DATA_V0{
				UsnJournalID:   ujd.UsnJournalID,
				StartUsn:       ujd.NextUsn,
				BytesToWaitFor: 1,
				// TODO ReturnOnlyOnClose
				//ReturnOnlyOnClose: 1,
				ReasonMask: mask,
			},
			MinMajorVersion: 2,
			MaxMajorVersion: 2,
		},
		watches: make(watches),
		buffer:  make([]byte, systemBufferSize),
	}

	return &v, nil
}

func openVolume(path string) (syscall.Handle, error) {
	name, err := getVolumeName(path)
	if err != nil {
		return syscall.InvalidHandle, errors.Wrap(err)
	}

	nameUTF16, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return syscall.InvalidHandle, errors.Wrap(err)
	}

	hVolume, err := syscall.CreateFile(nameUTF16,
		win.FILE_LIST_DIRECTORY,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_OVERLAPPED,
		0)
	if err != nil {
		return syscall.InvalidHandle, errors.Wrap(err)
	}

	supported, err := win.IsSupportedUsnJournal(hVolume)
	if err != nil {
		syscall.CloseHandle(hVolume)
		return syscall.InvalidHandle, errors.Wrap(err)
	}
	if !supported {
		syscall.CloseHandle(hVolume)
		return syscall.InvalidHandle, errors.New("The USN journal is not supported.")
	}

	return hVolume, nil
}

func getVolumePathName(path string) (string, error) {
	pathUTF16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", errors.Wrap(err)
	}

	lengthPathName := 256
	bufferPathName := make([]uint16, lengthPathName)
	err = win.GetVolumePathName(pathUTF16, &bufferPathName[0], uint32(lengthPathName))
	if err != nil {
		return "", errors.Wrap(err)
	}

	return syscall.UTF16ToString(bufferPathName), nil
}

func getVolumeName(path string) (string, error) {
	pathName, err := getVolumePathName(path)
	if err != nil {
		return "", errors.Wrap(err)
	}

	bufferPathName, err := syscall.UTF16PtrFromString(pathName)
	if err != nil {
		return "", errors.Wrap(err)
	}

	lengthName := 256
	bufferName := make([]uint16, lengthName)
	err = win.GetVolumeNameForVolumeMountPoint(bufferPathName, &bufferName[0], uint32(lengthName))
	if err != nil {
		return "", errors.Wrap(err)
	}

	for i, v := range bufferName {
		if v == 0 {
			bufferName[i-1] = 0
			break
		}
	}

	return syscall.UTF16ToString(bufferName), nil
}
