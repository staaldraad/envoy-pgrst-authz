package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func main() {

	hmacSecretPtr := flag.String("hmac", "", "a secret to sign the jwt")
	rolePtr := flag.String("role", "anon", "a role to give to the generated token")
	flag.Parse()

	if *hmacSecretPtr == "" {
		fmt.Println("requires --hmac value")
		return
	}
	// create jwt for testing with
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":   "bar",
		"nbf":  time.Date(2025, 01, 25, 12, 0, 0, 0, time.UTC).Unix(),
		"role": *rolePtr,
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, _ := token.SignedString([]byte(*hmacSecretPtr))
	fmt.Println(tokenString)
}
