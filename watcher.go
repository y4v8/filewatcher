package filewatcher

import (
	"github.com/y4v8/errors"
	"github.com/y4v8/filewatcher/win"
	"strings"
	"syscall"
	"unsafe"
)

const (
	keySystem uint32 = iota
	keyQuit
	keyChange
)

type Event struct {
	Name   string
	Reason win.UsnReason
}

type watcher struct {
	port       syscall.Handle
	reasonMask win.UsnReason
	volumes    volumes
	events     chan Event
	action     chan watchAction
	done       chan bool
}

func NewWatcher(events chan Event) (*watcher, error) {
	port, err := syscall.CreateIoCompletionPort(syscall.InvalidHandle, 0, 0, 0)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	w := &watcher{
		port:       port,
		reasonMask: 0xFFFFFFFF,
		volumes:    make(volumes),
		events:     events,
		action:     make(chan watchAction, 16),
		done:       make(chan bool),
	}

	// TODO mask
	w.reasonMask =
		win.USN_REASON_DATA_OVERWRITE |
			win.USN_REASON_DATA_EXTEND |
			win.USN_REASON_DATA_TRUNCATION |
			win.USN_REASON_FILE_CREATE |
			win.USN_REASON_FILE_DELETE |
			win.USN_REASON_RENAME_OLD_NAME |
			win.USN_REASON_RENAME_NEW_NAME

	return w, nil
}

func (w *watcher) Add(path string) error {
	return w.changeWatch(path, actionAdd)
}

func (w *watcher) Remove(path string) error {
	return w.changeWatch(path, actionRemove)
}

func (w *watcher) changeWatch(path string, action action) error {
	err := syscall.PostQueuedCompletionStatus(w.port, 0, keyChange, nil)
	if err != nil {
		return errors.Wrap(err)
	}

	wa := watchAction{
		action: action,
		path:   path,
	}
	w.action <- wa

	return nil
}

func (w *watcher) Close() error {
	err := syscall.PostQueuedCompletionStatus(w.port, 0, keyQuit, nil)
	if err != nil {
		return errors.Wrap(err)
	}

	<-w.done

	err = nil
	for _, v := range w.volumes {
		err = errors.Wrap(err, syscall.CloseHandle(v.handle))
	}
	return errors.Wrap(err, syscall.CloseHandle(w.port))
}

func (w *watcher) Start() {
	var n, key uint32
	var ov *syscall.Overlapped
	var err error

loop:
	for {
		err = syscall.GetQueuedCompletionStatus(w.port, &n, &key, &ov, syscall.INFINITE)
		switch {
		case key == keyQuit:
			break loop
		case key == keyChange:
			err = w.changeHandler()
		case err != nil:
			err = errors.Wrap(err)
		default:
			err = w.systemHandler(n, ov)
		}
	}

	close(w.done)
}

func (w *watcher) systemHandler(n uint32, ov *syscall.Overlapped) (err error) {
	if n == 0 {
		return errors.New("reading is empty")
	}

	var usnRecord *win.USN_RECORD_V2
	var name string

	v := (*volume)(unsafe.Pointer(ov))
	if v == nil {
		return errors.New("pointer is nil")
	}

	begin := unsafe.Pointer(&v.buffer[0])

	nextUSN := *(*uint64)(begin)
	if nextUSN == v.urd.StartUsn {
		return errors.New("nextUSN eq startUSN")
	}
	v.urd.StartUsn = nextUSN

	pos := uintptr(begin)
	max := pos + uintptr(n)
loop:
	for pos += 8; pos < max; pos += uintptr(usnRecord.RecordLength) {
		usnRecord = (*win.USN_RECORD_V2)(unsafe.Pointer(pos))

		name, err = win.GetFileNameByID(v.handle, usnRecord.FileReferenceNumber)
		if err != nil {
			name, err = win.GetFileNameByID(v.handle, usnRecord.ParentFileReferenceNumber)
			if err != nil {
				continue loop
			}
			name = name + "\\" + usnRecord.FileName()
		}
		name = strings.ToLower(name)

		for _, wa := range v.watches {
			if strings.HasPrefix(name, wa.path) {
				w.events <- Event{
					Name:   wa.volumeName + name,
					Reason: usnRecord.Reason & w.reasonMask,
				}
				continue loop
			}
		}
	}

	return w.startWatch(v)
}

func (w *watcher) changeHandler() error {
	var err error
	var v *volume

	wa := <-w.action

	if wa.action == actionAdd {
		v, err = w.addWatch(wa.path)
	} else if wa.action == actionRemove {
		v, err = w.removeWatch(wa.path)
	}

	if err != nil {
		return err
	}
	if v != nil {
		return w.startWatch(v)
	}

	return nil
}

func (w *watcher) startWatch(v *volume) error {
	err := syscall.CancelIo(v.handle)
	if err != nil {
		return errors.Wrap(err)
	}

	var sizeUrd uint32 = uint32(unsafe.Sizeof(v.urd))
	var bytesReturned uint32

	err = syscall.DeviceIoControl(v.handle, win.FSCTL_READ_USN_JOURNAL, (*byte)(unsafe.Pointer(&v.urd)), sizeUrd,
		&v.buffer[0], systemBufferSize, &bytesReturned, &v.ov)
	if err != nil && err != syscall.ERROR_IO_PENDING {
		return errors.Wrap(err)
	}

	return nil
}

func (w *watcher) removeWatch(path string) (*volume, error) {
	wa, err := newWatch(path)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	v, ok := w.volumes[wa.volume]
	if !ok {
		return nil, errors.New("path not found")
	}

	_, ok = v.watches[wa.path]
	if !ok {
		return nil, errors.New("path not found")
	}

	delete(v.watches, wa.path)

	if len(v.watches) == 0 {
		delete(w.volumes, wa.volume)

		err = syscall.CancelIo(v.handle)
		if err != nil {
			return nil, errors.Wrap(err)
		}
		return nil, nil
	}

	return v, nil
}

func (w *watcher) addWatch(path string) (*volume, error) {
	wa, err := newWatch(path)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	volume, ok := w.volumes[wa.volume]
	if !ok {
		volume, err = newVolume(path, w.reasonMask)
		if err != nil {
			return nil, errors.Wrap(err)
		}

		err = w.queueVolume(volume)
		if err != nil {
			return nil, errors.Wrap(err)
		}

		w.volumes[wa.volume] = volume
	}

	_, ok = volume.watches[wa.path]
	if !ok {
		volume.watches[wa.path] = wa

		w.startWatch(volume)
	}

	return volume, nil
}

func (w *watcher) queueVolume(v *volume) error {
	port, err := syscall.CreateIoCompletionPort(v.handle, w.port, keySystem, 0)
	if err != nil {
		return errors.Wrap(err)
	}
	if port != w.port {
		return errors.New("The function CreateIoCompletionPort returned a wrong port.")
	}

	return nil
}
