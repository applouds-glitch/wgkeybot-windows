//go:build windows

package winbridge

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dataBlob — Windows DATA_BLOB structure (crypt32.dll).
type dataBlob struct {
	Size uint32
	Data *byte
}

var (
	crypt32           = windows.NewLazySystemDLL("crypt32.dll")
	procProtectData   = crypt32.NewProc("CryptProtectData")
	procUnprotectData = crypt32.NewProc("CryptUnprotectData")
	kernel32dll       = windows.NewLazySystemDLL("kernel32.dll")
	procLocalFree     = kernel32dll.NewProc("LocalFree")
)

// CRYPTPROTECT_UI_FORBIDDEN — не показывать UI при шифровании/расшифровке.
const cryptProtectUIForbidden = 0x1

// encryptDPAPI шифрует данные через Windows DPAPI.
// Результат может расшифровать только тот же пользователь на той же машине.
func encryptDPAPI(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("dpapi: empty input")
	}
	in := dataBlob{Size: uint32(len(plaintext)), Data: &plaintext[0]}
	var out dataBlob

	r, _, err := procProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0,
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.Data)))

	result := make([]byte, out.Size)
	copy(result, unsafe.Slice(out.Data, out.Size))
	return result, nil
}

// decryptDPAPI расшифровывает данные, зашифрованные encryptDPAPI.
func decryptDPAPI(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("dpapi: empty input")
	}
	in := dataBlob{Size: uint32(len(ciphertext)), Data: &ciphertext[0]}
	var out dataBlob

	r, _, err := procUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0,
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.Data)))

	result := make([]byte, out.Size)
	copy(result, unsafe.Slice(out.Data, out.Size))
	return result, nil
}
