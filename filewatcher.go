package filewatcher

import (
	"log"
	"syscall"
	"time"
	"unsafe"
	"context"

	. "github.com/y4v8/filewatcher/win"
)

const (
	firstUsnRecordOffset uint32 = 8
	itemCount                   = 1024
	bufSize                     = uint32(unsafe.Sizeof(USN_RECORD_V2{}))*itemCount + 8
	checkInterval               = time.Second
)

type Watcher struct {
	volume        string
	usnReasonMask uint32
}

func NewWatcher(volume string, usnReasonMask uint32) *Watcher {
	w := &Watcher{
		volume:        volume,
		usnReasonMask: usnReasonMask,
	}

	return w
}

type UsnRecordHandler func(hVolume syscall.Handle, info *USN_RECORD_V2)

func (w *Watcher) Start(ctx context.Context, usnRecordHandler UsnRecordHandler) error {
	hVolume, err := OpenVolume("\\\\.\\" + w.volume)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(hVolume)

	ujd, err := GetUsnJournalData(hVolume)
	if err != nil {
		return err
	}
	nextUSN := ujd.NextUsn

	var buf [bufSize]byte
	var uLength uint32
	var usnRecord *USN_RECORD_V2

	urd := READ_USN_JOURNAL_DATA_V1{
		READ_USN_JOURNAL_DATA_V0: READ_USN_JOURNAL_DATA_V0{
			StartUsn:          nextUSN,
			ReasonMask:        w.usnReasonMask,
			ReturnOnlyOnClose: 1,
			UsnJournalID:      ujd.UsnJournalID,
		},
		MaxMajorVersion: 2,
		MinMajorVersion: 2,
	}

	sizeUrd := uint32(unsafe.Sizeof(urd))

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		err = syscall.DeviceIoControl(hVolume,
			FSCTL_READ_USN_JOURNAL,
			(*byte)(unsafe.Pointer(&urd)),
			sizeUrd,
			(*byte)(unsafe.Pointer(&buf)),
			bufSize,
			&uLength,
			nil)
		if err != nil {
			log.Println("[1] continue:", err)
			time.Sleep(checkInterval)
			continue
		}

		nextUSN = *(*uint64)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf))))
		if nextUSN == urd.StartUsn {
			log.Println("[2] continue:", err)
			time.Sleep(checkInterval)
			continue
		}
		urd.StartUsn = nextUSN

		if uLength == firstUsnRecordOffset {
			log.Println("[3] continue:", err)
			time.Sleep(checkInterval)
			continue
		}

		begin := uintptr(unsafe.Pointer(&buf))
		for pos := firstUsnRecordOffset; pos < uLength; pos += usnRecord.RecordLength {
			usnRecord = (*USN_RECORD_V2)(unsafe.Pointer(begin + uintptr(pos)))

			usnRecordHandler(hVolume, usnRecord)
		}
	}

	return nil
}
