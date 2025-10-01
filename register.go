package aesecb

import (
	aesecb "github.com/ekanant/xk6-aes-ecb/aes_ecb"
	"go.k6.io/k6/js/modules"
)

func init() {
	modules.Register("k6/x/aes-ecb", new(aesecb.AesEcb))
}
