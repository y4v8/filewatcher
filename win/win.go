package win

import (
	"syscall"
	"unsafe"
	"github.com/y4v8/errors"
)

var (
	modKernel32                          = syscall.NewLazyDLL("kernel32.dll")
	procGetVolumeInformationByHandleW    = modKernel32.NewProc("GetVolumeInformationByHandleW")
	procOpenFileById                     = modKernel32.NewProc("OpenFileById")
	procGetFileInformationByHandleEx     = modKernel32.NewProc("GetFileInformationByHandleEx")
	procGetVolumePathName                = modKernel32.NewProc("GetVolumePathNameW")
	procGetVolumeNameForVolumeMountPoint = modKernel32.NewProc("GetVolumeNameForVolumeMountPointW")
)

// Represents an update sequence number (USN) change journal, its records,
// and its capacity. This structure is the output buffer for the
// FSCTL_QUERY_USN_JOURNAL control code.
type USN_JOURNAL_DATA_V0 struct {
	UsnJournalID    uint64
	FirstUsn        uint64
	NextUsn         uint64
	LowestValidUsn  uint64
	MaxUsn          uint64
	MaximumSize     uint64
	AllocationDelta uint64
}

// Represents an update sequence number (USN) change journal, its records,
// and its capacity. This structure is the output buffer for the
// FSCTL_QUERY_USN_JOURNAL control code.
type USN_JOURNAL_DATA_V1 struct {
	USN_JOURNAL_DATA_V0

	MinMajorVersion uint16
	MaxMajorVersion uint16
}

// Represents an update sequence number (USN) change journal, its records,
// and its capacity. This structure is the output buffer for the
// FSCTL_QUERY_USN_JOURNAL control code.
type USN_JOURNAL_DATA_V2 struct {
	USN_JOURNAL_DATA_V1

	Flags                       uint32
	RangeTrackChunkSize         uint64
	RangeTrackFileSizeThreshold uint64
}

// Contains information defining a set of update sequence number (USN)
// change journal records to return to the calling process. It is used by
// the FSCTL_QUERY_USN_JOURNAL and FSCTL_READ_USN_JOURNAL control codes.
type READ_USN_JOURNAL_DATA_V0 struct {
	StartUsn          uint64
	ReasonMask        ReasonMask
	ReturnOnlyOnClose uint32
	Timeout           uint64
	BytesToWaitFor    uint64
	UsnJournalID      uint64
}

// Contains information defining a set of update sequence number (USN)
// change journal records to return to the calling process. It is used by
// the FSCTL_QUERY_USN_JOURNAL and FSCTL_READ_USN_JOURNAL control codes.
type READ_USN_JOURNAL_DATA_V1 struct {
	READ_USN_JOURNAL_DATA_V0

	MinMajorVersion uint16
	MaxMajorVersion uint16
}

// Contains information defining the boundaries for and starting place of an
// enumeration of update sequence number (USN) change journal records for
// ReFS volumes. It is used as the input buffer for the FSCTL_ENUM_USN_DATA
// control code.
type MFT_ENUM_DATA_V0 struct {
	StartFileReferenceNumber uint64
	LowUsn                   uint64
	HighUsn                  uint64
}

// Contains information defining the boundaries for and starting place of an
// enumeration of update sequence number (USN) change journal records for
// ReFS volumes. It is used as the input buffer for the FSCTL_ENUM_USN_DATA
// control code.
type MFT_ENUM_DATA_V1 struct {
	MFT_ENUM_DATA_V0

	MinMajorVersion uint16
	MaxMajorVersion uint16
}

// Contains the information for an update sequence number (USN) change
// journal version 2.0 record.
type USN_RECORD_V2 struct {
	RecordLength              uint32
	MajorVersion              uint16
	MinorVersion              uint16
	FileReferenceNumber       uint64
	ParentFileReferenceNumber uint64
	USN                       uint64
	TimeStamp                 uint64
	Reason                    ReasonMask
	SourceInfo                uint32
	SecurityId                uint32
	FileAttributes            uint32
	FileNameLength            uint16
	FileNameOffset            uint16
	fileName                  [260]uint16
}

func (r *USN_RECORD_V2) FileName() string {
	return syscall.UTF16ToString(r.fileName[0:r.FileNameLength/2])
}

type uint128 struct {
	H uint64
	L uint64
}

// Contains the information for an update sequence number (USN) change
// journal version 3.0 record. The version 2.0 record is defined by the
// USN_RECORD_V2 structure (also called USN_RECORD structure).
type USN_RECORD_V3 struct {
	RecordLength              uint32
	MajorVersion              uint16
	MinorVersion              uint16
	FileReferenceNumber       uint128
	ParentFileReferenceNumber uint128
	Usn                       uint64
	TimeStamp                 uint64
	Reason                    uint32
	SourceInfo                uint32
	SecurityId                uint32
	FileAttributes            uint32
	FileNameLength            uint16
	FileNameOffset            uint16
	FileName                  [260]uint16
}

// Contains the information for an update sequence number (USN) common header
// which is common through USN_RECORD_V2, USN_RECORD_V3 and USN_RECORD_V4.
type USN_RECORD_COMMON_HEADER struct {
	RecordLength uint32
	MajorVersion uint16
	MinorVersion uint16
}

// Contains the offset and length for an update sequence number (USN) record
// extent.
type USN_RECORD_EXTENT struct {
	Offset uint64
	Length uint64
}

// Contains the information for an update sequence number (USN) change
// journal version 4.0 record. The version 2.0 and 3.0 records are
// defined by the USN_RECORD_V2 (also called USN_RECORD) and USN_RECORD_V3
// structures respectively.
type USN_RECORD_V4 struct {
	Header                    USN_RECORD_COMMON_HEADER
	FileReferenceNumber       uint128
	ParentFileReferenceNumber uint128
	Usn                       uint64
	Reason                    uint32
	SourceInfo                uint32
	RemainingExtents          uint32
	NumberOfExtents           uint16
	ExtentSize                uint16
	Extents                   [1]USN_RECORD_EXTENT
}

// Retrieves information about the file system and volume associated with
// the specified root directory.
func getVolumeInformationByHandle(hFile syscall.Handle,
	lpVolumeNameBuffer *uint16,
	nVolumeNameSize uint32,
	lpVolumeSerialNumber *uint32,
	lpMaximumComponentLength *uint32,
	lpFileSystemFlags *uint32,
	lpFileSystemNameBuffer *uint16,
	nFileSystemNameSize uint32) (uintptr, error) {

	r1, _, err := procGetVolumeInformationByHandleW.Call(
		uintptr(hFile),
		uintptr(unsafe.Pointer(lpVolumeNameBuffer)),
		uintptr(nVolumeNameSize),
		uintptr(unsafe.Pointer(lpVolumeSerialNumber)),
		uintptr(unsafe.Pointer(lpMaximumComponentLength)),
		uintptr(unsafe.Pointer(lpFileSystemFlags)),
		uintptr(unsafe.Pointer(lpFileSystemNameBuffer)),
		uintptr(nFileSystemNameSize),
	)

	return r1, err
}

// Specifies the type of ID that is being used.
type FILE_ID_DESCRIPTOR struct {
	DwSize    uint32
	Type      uint32
	FileId    uint64
	ExtFileId uint64
}

// Contains the security descriptor of an object and specifies whether
// the handle retrieved by specifying this structure is inheritable.
type SECURITY_ATTRIBUTES struct {
	NLength              uint32
	LpSecurityDescriptor uint32
	BInheritHandle       uint32
}

// Receives the file name. Used for any handles.
// Use only when calling GetFileInformationByHandleEx.
type FILE_NAME_INFO struct {
	FileNameLength uint32
	FileName       [260]uint16
}

// Opens the file that matches the specified identifier.
func OpenFileById(hFile syscall.Handle,
	lpFileID *FILE_ID_DESCRIPTOR,
	dwDesiredAccess uint32,
	dwShareMode uint32,
	lpSecurityAttributes *SECURITY_ATTRIBUTES,
	dwFlags uint32) (syscall.Handle, error) {
	r1, _, err := procOpenFileById.Call(
		uintptr(hFile),
		uintptr(unsafe.Pointer(lpFileID)),
		uintptr(dwDesiredAccess),
		uintptr(dwShareMode),
		uintptr(unsafe.Pointer(lpSecurityAttributes)),
		uintptr(dwFlags),
	)
	h := syscall.Handle(r1)
	if h != syscall.InvalidHandle {
		err = nil
	}

	return h, err
}

// Retrieves file information for the specified file.
func GetFileInformationByHandleEx(hFile syscall.Handle,
	fileInformationClass uint32,
	lpFileInformation unsafe.Pointer,
	dwBufferSize uint32) error {
	r1, _, err := procGetFileInformationByHandleEx.Call(
		uintptr(hFile),
		uintptr(fileInformationClass),
		uintptr(lpFileInformation),
		uintptr(dwBufferSize),
	)
	if r1 == 1 {
		return nil
	}

	return err
}

const (
	// The specified volume supports update sequence number (USN) journals.
	FILE_SUPPORTS_USN_JOURNAL = 0x02000000

	// The control code to query for information on the current update
	// sequence number (USN) change journal, its records, and its capacity.
	FSCTL_QUERY_USN_JOURNAL = 9<<16 | 61<<2 // 590068

	// The control code to retrieve the set of update sequence number (USN)
	// change journal records between two specified USN values.
	FSCTL_READ_USN_JOURNAL = 9<<16 | 46<<2 | 3 // 590011

	// The control code to enumerate the update sequence number (USN) data
	// between two specified boundaries to obtain master file table (MFT)
	// records.
	FSCTL_ENUM_USN_DATA = 9<<16 | 44<<2 | 3 // 590003

	// The control code to retrieve the first file record that is in use
	// and is of a lesser than or equal ordinal value to the requested file
	// reference number.
	FSCTL_GET_NTFS_FILE_RECORD = 9<<16 | 26<<2 // 589928
)

type ReasonMask uint32

const (
	// Data in the file or directory is overwritten.
	USN_REASON_DATA_OVERWRITE ReasonMask = 0x00000001

	// The file or directory is added to.
	USN_REASON_DATA_EXTEND = 0x00000002

	// The file or directory is truncated.
	USN_REASON_DATA_TRUNCATION = 0x00000004

	// Data in one or more named data streams for the file is overwritten.
	USN_REASON_NAMED_DATA_OVERWRITE = 0x00000010

	// One or more named data streams for the file were added to.
	USN_REASON_NAMED_DATA_EXTEND = 0x00000020

	// One or more named data streams for the file is truncated.
	USN_REASON_NAMED_DATA_TRUNCATION = 0x00000040

	// The file or directory is created for the first time.
	USN_REASON_FILE_CREATE = 0x00000100

	// The file or directory is deleted.
	USN_REASON_FILE_DELETE = 0x00000200

	// The user makes a change to the file or directory extended attributes.
	// These NTFS file system attributes are not accessible to Windows-based
	// applications.
	USN_REASON_EA_CHANGE = 0x00000400

	// A change is made in the access permissions to the file or directory.
	USN_REASON_SECURITY_CHANGE = 0x00000800

	// The file or directory is renamed, and the file name in the USN_RECORD
	// structure holding this journal record is the previous name.
	USN_REASON_RENAME_OLD_NAME = 0x00001000

	// The file or directory is renamed, and the file name in the USN_RECORD
	// structure holding this journal record is the new name.
	USN_REASON_RENAME_NEW_NAME = 0x00002000

	// A user changed the FILE_ATTRIBUTE_NOT_CONTENT_INDEXED attribute.
	// That is, the user changed the file or directory from one that
	// can be content indexed to one that cannot, or vice versa. (Content
	// indexing permits rapid searching of data by building a database of
	// selected content.)
	USN_REASON_INDEXABLE_CHANGE = 0x00004000

	// A user has either changed one or more file or directory attributes (such
	// as the read-only, hidden, system, archive, or sparse attribute), or one
	// or more time stamps.
	USN_REASON_BASIC_INFO_CHANGE = 0x00008000

	// An NTFS file system hard link is added to or removed from the file or
	// directory. An NTFS file system hard link, similar to a POSIX hard link,
	// is one of several directory entries that see the same file or directory.
	USN_REASON_HARD_LINK_CHANGE = 0x00010000

	// The compression state of the file or directory is changed from or to
	// compressed.
	USN_REASON_COMPRESSION_CHANGE = 0x00020000

	// The file or directory is encrypted or decrypted.
	USN_REASON_ENCRYPTION_CHANGE = 0x00040000

	// The object identifier of the file or directory is changed.
	USN_REASON_OBJECT_ID_CHANGE = 0x00080000

	// The reparse point contained in the file or directory is changed,
	// or a reparse point is added to or deleted from the file or directory.
	USN_REASON_REPARSE_POINT_CHANGE = 0x00100000

	// A named stream is added to or removed from the file or directory,
	// or a named stream is renamed.
	USN_REASON_STREAM_CHANGE = 0x00200000

	// The given stream is modified through a TxF transaction.
	USN_REASON_TRANSACTED_CHANGE = 0x00400000

	// A user changed the state of the FILE_ATTRIBUTE_INTEGRITY_STREAM
	// attribute for the given stream.
	USN_REASON_INTEGRITY_CHANGE = 0x00800000

	// The file or directory is closed.
	USN_REASON_CLOSE = 0x80000000
)

// The list of short names for USN reason code flags.
var ReasonNames = map[ReasonMask]string{
	USN_REASON_DATA_OVERWRITE:        "DATA_OVERWRITE",
	USN_REASON_DATA_EXTEND:           "DATA_EXTEND",
	USN_REASON_DATA_TRUNCATION:       "DATA_TRUNCATION",
	USN_REASON_NAMED_DATA_OVERWRITE:  "NAMED_DATA_OVERWRITE",
	USN_REASON_NAMED_DATA_EXTEND:     "NAMED_DATA_EXTEND",
	USN_REASON_NAMED_DATA_TRUNCATION: "NAMED_DATA_TRUNCATION",
	USN_REASON_FILE_CREATE:           "FILE_CREATE",
	USN_REASON_FILE_DELETE:           "FILE_DELETE",
	USN_REASON_EA_CHANGE:             "EA_CHANGE",
	USN_REASON_SECURITY_CHANGE:       "SECURITY_CHANGE",
	USN_REASON_RENAME_OLD_NAME:       "RENAME_OLD_NAME",
	USN_REASON_RENAME_NEW_NAME:       "RENAME_NEW_NAME",
	USN_REASON_INDEXABLE_CHANGE:      "INDEXABLE_CHANGE",
	USN_REASON_BASIC_INFO_CHANGE:     "BASIC_INFO_CHANGE",
	USN_REASON_HARD_LINK_CHANGE:      "HARD_LINK_CHANGE",
	USN_REASON_COMPRESSION_CHANGE:    "COMPRESSION_CHANGE",
	USN_REASON_ENCRYPTION_CHANGE:     "ENCRYPTION_CHANGE",
	USN_REASON_OBJECT_ID_CHANGE:      "OBJECT_ID_CHANGE",
	USN_REASON_REPARSE_POINT_CHANGE:  "REPARSE_POINT_CHANGE",
	USN_REASON_STREAM_CHANGE:         "STREAM_CHANGE",
	USN_REASON_TRANSACTED_CHANGE:     "TRANSACTED_CHANGE",
	USN_REASON_INTEGRITY_CHANGE:      "INTEGRITY_CHANGE",
	USN_REASON_CLOSE:                 "CLOSE",
}

const (
	// For a directory, the right to list the contents of the directory.
	FILE_LIST_DIRECTORY = 1

	// The right to read file attributes.
	FILE_READ_ATTRIBUTES = 0x80

	// The file name should be retrieved. Used for any handles.
	// Use only when calling GetFileInformationByHandleEx. See FILE_NAME_INFO.
	FILE_NAME_INFO_BY_HANDLE = 2
)

// Retrieves the filename for the specified volume and file identifier.
func GetFileNameByID(hVolume syscall.Handle, fileID uint64) (string, error) {
	fd := FILE_ID_DESCRIPTOR{}
	fd.DwSize = uint32(unsafe.Sizeof(fd))
	fd.FileId = fileID

	h, err := OpenFileById(hVolume,
		&fd,
		0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.FILE_FLAG_BACKUP_SEMANTICS)
	if err != nil {
		return "", errors.Wrap(err)
	}
	defer syscall.CloseHandle(h)

	fileNameInfo := FILE_NAME_INFO{}
	sizeFileNameInfo := uint32(unsafe.Sizeof(fileNameInfo))
	err = GetFileInformationByHandleEx(h, FILE_NAME_INFO_BY_HANDLE, unsafe.Pointer(&fileNameInfo), sizeFileNameInfo)
	if err == syscall.ERROR_MORE_DATA {

		sizeFileNameInfo = (4 + fileNameInfo.FileNameLength) / 2
		buf := make([]uint16, sizeFileNameInfo)
		err = GetFileInformationByHandleEx(h, FILE_NAME_INFO_BY_HANDLE, unsafe.Pointer(&buf[0]), sizeFileNameInfo*2)

		if err == nil {
			return syscall.UTF16ToString(buf[2: 2+fileNameInfo.FileNameLength/2]), nil
		}
	}
	if err != nil {
		return "", errors.Wrap(err)
	}

	return syscall.UTF16ToString(fileNameInfo.FileName[0: fileNameInfo.FileNameLength/2]), nil
}

// Checks the USN journal support for the volume.
func IsSupportedUsnJournal(hFile syscall.Handle) (bool, error) {
	var lpFileSystemFlags uint32
	res, err := getVolumeInformationByHandle(hFile,
		nil,
		0,
		nil,
		nil,
		&lpFileSystemFlags,
		nil,
		0)
	if res == 0 {
		return false, err
	}
	return lpFileSystemFlags&FILE_SUPPORTS_USN_JOURNAL != 0, nil
}

func GetUsnJournalData(hFile syscall.Handle) (*USN_JOURNAL_DATA_V2, error) {
	var bytesReturned uint32
	var ujd USN_JOURNAL_DATA_V2
	err := syscall.DeviceIoControl(hFile, FSCTL_QUERY_USN_JOURNAL, nil, 0,
		(*byte)(unsafe.Pointer(&ujd)), uint32(unsafe.Sizeof(ujd)), &bytesReturned, nil)

	return &ujd, err
}

func GetVolumePathName(filename *uint16, pathname *uint16, length uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procGetVolumePathName.Addr(), 3, uintptr(unsafe.Pointer(filename)), uintptr(unsafe.Pointer(pathname)), uintptr(length))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func GetVolumeNameForVolumeMountPoint(volumeMountPoint *uint16, volumeName *uint16, length uint32) (err error) {
	r1, _, e1 := syscall.Syscall(procGetVolumeNameForVolumeMountPoint.Addr(), 3, uintptr(unsafe.Pointer(volumeMountPoint)), uintptr(unsafe.Pointer(volumeName)), uintptr(length))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}
