package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"

	auth_pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/fsnotify/fsnotify"
	"github.com/golang-jwt/jwt/v4"
	"github.com/open-policy-agent/opa/v1/rego"
	"google.golang.org/grpc"
)

type AuthServer struct {
	pq         rego.PreparedEvalQuery
	hmacSecret []byte
}

type ParsedInput struct {
	Path    string                 `json:"path"`
	Table   string                 `json:"table"`
	Select  []string               `json:"select"`
	Filters map[string]string      `json:"filters"`
	Method  string                 `json:"method"`
	Jwt     map[string]interface{} `json:"jwt"`
}

type Allowed struct {
	Allowed bool   `json:"allow"`
	Reason  string `json:"reason,omitempty"`
}

func (server *AuthServer) Check(ctx context.Context, request *auth_pb.CheckRequest) (*auth_pb.CheckResponse, error) {

	path := request.Attributes.Request.Http.Path[1:]
	parsedInput := parsePath(path)

	if authString, ok := request.Attributes.Request.Http.Headers["authorization"]; ok {
		// validate token
		jwt, err := validateToken(authString, server.hmacSecret)
		if err == nil && jwt != nil {
			parsedInput.Jwt = jwt
		}
	}

	// add method
	switch request.Attributes.Request.Http.Method {
	case "GET":
		parsedInput.Method = "SELECT"
	case "POST":
		parsedInput.Method = "INSERT"
		// check if INSERT or UPSERT POST
		if h, ok := request.Attributes.Request.Http.Headers["prefer"]; ok {
			if h == "resolution=merge-duplicates" {
				parsedInput.Method = "UPSERT"
			}
		}
	case "PATCH":
		parsedInput.Method = "UPDATE"
	case "PUT":
		parsedInput.Method = "UPSERT"
	case "DELETE":
		parsedInput.Method = "DELETE"
	}

	rs, err := server.pq.Eval(ctx, rego.EvalInput(parsedInput))
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("request not allowed")
	}

	if rs[0].Expressions[0].Value == false {
		fmt.Println("blocked request by policy")
		return nil, fmt.Errorf("request not allowed")
	}

	return &auth_pb.CheckResponse{
		HttpResponse: &auth_pb.CheckResponse_OkResponse{
			OkResponse: &auth_pb.OkHttpResponse{},
		},
	}, nil
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

func parsePath(path string) ParsedInput {
	parsedInput := ParsedInput{Path: path, Filters: make(map[string]string)}
	u, _ := url.Parse(path)
	query := u.Query()
	parsedInput.Table = u.Path
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
	return parsedInput
}

func loadRego(path string) (rego.PreparedEvalQuery, error) {
	ctx := context.Background()
	// load rego
	authzFile, err := os.Open(path)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer authzFile.Close()

	// read rego file
	module, err := io.ReadAll(authzFile)
	if err != nil {
		log.Fatalf("error reading file: %v", err)
	}
	r := rego.New(
		rego.Query("data.authz.allow"),
		rego.Module("authz.rego", string(module)),
	)
	// Prepare for evaluation
	pq, err := r.PrepareForEval(ctx)

	if err != nil {
		fmt.Println(err)
		return pq, err
	}
	return pq, nil
}

func watchRego(server *AuthServer) {

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("ERROR", err)
	}
	defer watcher.Close()

	//
	done := make(chan bool)

	//
	go func() {
		for {
			select {
			// watch for events
			case event := <-watcher.Events:
				if event.Op.String() == "WRITE" {
					// reload the file
					pq, _ := loadRego("auth.rego")
					server.pq = pq
				}
				// watch for errors
			case err := <-watcher.Errors:
				fmt.Println("ERROR", err)
			}
		}
	}()

	// out of the box fsnotify can watch a single file, or a single directory
	if err := watcher.Add("auth.rego"); err != nil {
		fmt.Println("ERROR", err)
	}

	pq, _ := loadRego("auth.rego")
	server.pq = pq
	<-done
}

func main() {
	endPoint := fmt.Sprintf("localhost:%d", 3001)
	listen, _ := net.Listen("tcp", endPoint)

	grpcServer := grpc.NewServer()

	hmacSecretPtr := flag.String("hmac", "", "a secret to sign the jwt")
	flag.Parse()

	if *hmacSecretPtr == "" {
		fmt.Println("requires --hmac value")
		return
	}

	// register envoy proto server
	server := &AuthServer{hmacSecret: []byte(*hmacSecretPtr)}

	// load rego and keep watching for changes
	go watchRego(server)

	auth_pb.RegisterAuthorizationServer(grpcServer, server)

	fmt.Println("Server started at port 3001")
	grpcServer.Serve(listen)
}
