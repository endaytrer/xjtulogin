package main

import (
	"fmt"

	"github.com/endaytrer/xjtulogin"
)

func main() {
	var username, password string

	fmt.Printf("Username: ")
	fmt.Scanln(&username)
	fmt.Printf("Password: ")
	fmt.Scanln(&password)
	redir_url, err := xjtulogin.Login(
		"https://lms.xjtu.edu.cn/",
		username,
		password,
		func(phone string, send_otp func() error) (otp string, trust_device bool, err error) {
			fmt.Printf("MFA required. Phone: %s\n", phone)
			fmt.Println("Send OTP? (y/n)")
			var input string
			fmt.Scanln(&input)
			if input != "y" {
				return "", false, fmt.Errorf("OTP not sent")
			}
			if err := send_otp(); err != nil {
				return "", false, err
			}
			fmt.Printf("OTP sent to %s. Please enter the OTP: ", phone)
			fmt.Scanln(&input)
			fmt.Println("Trust this device? (y/n)")
			var trustDevice string
			fmt.Scanln(&trustDevice)
			if trustDevice == "y" {
				return input, true, nil
			}
			return input, false, nil
		},
	)
	if err != nil {
		fmt.Printf("Error occurred: %v\n", err)
		return
	}
	fmt.Printf("Login successful. Redirect URL: %s\n", redir_url)
}
