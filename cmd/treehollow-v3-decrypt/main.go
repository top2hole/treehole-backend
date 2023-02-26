package main

import (
	"fmt"
	"treehollow-v3-backend/pkg/utils"
	"github.com/SSSaaS/sssa-golang"
)

var (
	sliceNum int
	encryptedEmail string
	decryptedEmail string
)

func main() {
	fmt.Scanln(&sliceNum)
	keySlice := make([]string, sliceNum)
	for i := range keySlice {
		fmt.Scanln(&keySlice[i])
	}
	keyResult, _ := sssa.Combine(keySlice)
	fmt.Println(keyResult)
	fmt.Scanln(&encryptedEmail)
	decryptedEmail, _ := utils.AESDecrypt(encryptedEmail, keyResult)
	fmt.Println(decryptedEmail)
}