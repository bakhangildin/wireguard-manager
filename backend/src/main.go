package main

import (
	"log"
	"os"
)

func main() {
	var (
		adminUsername = os.Getenv("VPN_MANAGER_USERNAME")
		adminPassword = os.Getenv("VPN_MANAGER_PASSWORD")
		jwtSecret     = os.Getenv("JWT_SECRET")
		configPath    = "files/wg0.conf"
	)
	if len(adminUsername) == 0 || len(adminPassword) == 0 || len(jwtSecret) == 0 {
		log.Fatal("Username, pasword or secret missing\n\n" +
			"\texport VPN_MANAGER_USERNAME=\"test\"\n" +
			"\texport VPN_MANAGER_PASSWORD=\"test\"\n" +
			"\texport JWT_SECRET=\"sample_jwt_secret\"\n\n")
	}
	s := NewApiServer(":3000", adminUsername, adminPassword, jwtSecret, configPath, os.Stdout)
	s.Run()
}
