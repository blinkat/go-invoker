package main

import (
	"fmt"
	"github.com/blinkat/go-invoker"
)

func main() {
	ctypter, err := invoker.NewCrypter(invoker.ALGORITHM_ECDH, invoker.A256GCM, invoker.ECDH_SIZE_P521)
	if err != nil {
		fmt.Println(err)
		return
	}

	plaintext := "the test plain text."
	cip, err := ctypter.Encrypt([]byte(plaintext))
	fmt.Println("cipher text:", string(cip))

	if err != nil {
		fmt.Println(err)
		return
	}

	ret, err := ctypter.Decrypt(cip)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(ret)
}
