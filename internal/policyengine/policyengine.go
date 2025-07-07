package policyengine

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	auth_pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/golang-jwt/jwt"
)

type PolicyEngine interface {
	AuthzRequest(context.Context, *auth_pb.CheckRequest, []byte) (ok bool, err error) // takes a request and turns into the input expected by the policy engine
	LoadPolicy([]byte) error                                                          // loads the policy
	Init() error                                                                      // does  any necessary initialization
}

type ParsedInput struct {
	Path     string                 `json:"path"`
	Table    string                 `json:"table"`
	Function string                 `json:"function"`
	Select   []string               `json:"select"`
	Filters  map[string]string      `json:"filters"`
	Method   string                 `json:"method"`
	Jwt      map[string]interface{} `json:"jwt"`
}

func parsePath(hmacSecret []byte, request *auth_pb.AttributeContext_Request) ParsedInput {
	path := request.Http.Path[1:]
	parsedInput := ParsedInput{Path: path, Filters: make(map[string]string)}
	u, _ := url.Parse(path)
	query := u.Query()
	if strings.HasPrefix(u.Path, "rpc/") {
		parsedInput.Function = strings.Split(u.Path, "/")[1]
	} else {
		parsedInput.Table = u.Path
	}

	for q, p := range query {
		switch q {
		case "select":
			columns := strings.Split(p[0], ",")
			// remove casting
			for k, v := range columns {
				columns[k] = strings.SplitN(v, "::", 2)[0]
			}
			parsedInput.Select = columns
		default:
			parsedInput.Filters[q] = p[0]
		}
	}
	parsedInput.Method = extractSQLMethod(request.Http.Method, request.Http.Headers)
	parsedInput.Jwt = extractJWT(hmacSecret, request.Http.Headers)
	return parsedInput
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
