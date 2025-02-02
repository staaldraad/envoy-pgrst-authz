package policyengine

import (
	"context"
	"fmt"
	"strings"

	auth_pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang-jwt/jwt"
)

type PolicyEngine interface {
	AuthzRequest(context.Context, *auth_pb.CheckRequest, []byte) (ok bool, err error) // takes a request and turns into the input expected by the policy engine
	LoadPolicy([]byte) error                                                          // loads the policy
}

func extractJWT(hmacSecret []byte, headers map[string]string) jwt.MapClaims {
	if authString, ok := headers["authorization"]; ok {
		// validate token
		jwt, err := validateToken(authString, hmacSecret)
		if err == nil && jwt != nil {
			return jwt
		}
	}
	return nil
}

func validateToken(tokenString string, hmacSecret []byte) (jwt.MapClaims, error) {
	// remove bearer keyword if present
	if ts := strings.Split(tokenString, " "); len(ts) == 2 {
		tokenString = ts[1]
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return hmacSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}
	return nil, nil
}

func extractSQLMethod(method string, headers map[string]string) string {
	// add method
	switch method {
	case "GET":
		return "SELECT"
	case "POST":
		// check if INSERT or UPSERT POST
		if h, ok := headers["prefer"]; ok {
			if h == "resolution=merge-duplicates" {
				return "UPSERT"
			}
		}
		return "INSERT"
	case "PATCH":
		return "UPDATE"
	case "PUT":
		return "UPSERT"
	case "DELETE":
		return "DELETE"
	}
	return ""
}
