package aesecb

import (
	"bytes"
	"errors"
)

// Pad applies PKCS7, X923, or ISO7816 padding
func (AesEcb) Pad(data []byte, blockSize int, style string) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("invalid block size")
	}
	paddingLen := blockSize - (len(data) % blockSize)
	if paddingLen == 0 {
		paddingLen = blockSize
	}

	var padding []byte
	switch style {
	case "pkcs7":
		padding = bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	case "x923":
		padding = append(bytes.Repeat([]byte{0}, paddingLen-1), byte(paddingLen))
	case "iso7816":
		padding = append([]byte{0x80}, bytes.Repeat([]byte{0}, paddingLen-1)...)
	default:
		return nil, errors.New("unknown padding style")
	}

	return append(data, padding...), nil
}

// Unpad removes PKCS7, X9.23, or ISO7816 padding
func (AesEcb) Unpad(data []byte, blockSize int, style string) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("zero-length input cannot be unpadded")
	}
	if length%blockSize != 0 {
		return nil, errors.New("input data is not padded")
	}

	var paddingLen int
	switch style {
	case "pkcs7", "x923":
		paddingLen = int(data[length-1])
		if paddingLen < 1 || paddingLen > blockSize || paddingLen > length {
			return nil, errors.New("padding is incorrect")
		}
		if style == "pkcs7" {
			if !bytes.Equal(data[length-paddingLen:], bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)) {
				return nil, errors.New("pkcs7 padding is incorrect")
			}
		} else { // x923
			if !bytes.Equal(data[length-paddingLen:length-1], bytes.Repeat([]byte{0}, paddingLen-1)) {
				return nil, errors.New("ansi x.923 padding is incorrect")
			}
		}
	case "iso7816":
		lastIdx := bytes.LastIndexByte(data, 0x80)
		if lastIdx == -1 {
			return nil, errors.New("iso7816 padding marker not found")
		}
		paddingLen = length - lastIdx
		if paddingLen < 1 || paddingLen > blockSize || paddingLen > length {
			return nil, errors.New("padding is incorrect")
		}
		if paddingLen > 1 && !bytes.Equal(data[lastIdx+1:], bytes.Repeat([]byte{0}, paddingLen-1)) {
			return nil, errors.New("iso7816 padding is incorrect")
		}
	default:
		return nil, errors.New("unknown padding style")
	}

	return data[:length-paddingLen], nil
}
