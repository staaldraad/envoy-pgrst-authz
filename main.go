package main

import (
	"context"
	"flag"
	"fmt"
	"net"

	auth_pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/staaldraad/envoy-pgrst-auth/internal"
	"github.com/staaldraad/envoy-pgrst-auth/internal/policyengine"
	"google.golang.org/grpc"
)

type AuthServer struct {
	hmacSecret   []byte
	policyEngine policyengine.PolicyEngine
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

type Allowed struct {
	Allowed bool   `json:"allow"`
	Reason  string `json:"reason,omitempty"`
}

func (server *AuthServer) Check(ctx context.Context, request *auth_pb.CheckRequest) (*auth_pb.CheckResponse, error) {

	ok, err := server.policyEngine.AuthzRequest(ctx, request, server.hmacSecret)
	if !ok {
		return &auth_pb.CheckResponse{
			HttpResponse: &auth_pb.CheckResponse_DeniedResponse{
				DeniedResponse: &auth_pb.DeniedHttpResponse{},
			},
		}, fmt.Errorf("request not allowed by policy")
	}
	if err != nil {
		return &auth_pb.CheckResponse{
			HttpResponse: &auth_pb.CheckResponse_DeniedResponse{
				DeniedResponse: &auth_pb.DeniedHttpResponse{},
			},
		}, err
	}

	return &auth_pb.CheckResponse{
		HttpResponse: &auth_pb.CheckResponse_OkResponse{
			OkResponse: &auth_pb.OkHttpResponse{},
		},
	}, nil
}

func main() {
	endPoint := fmt.Sprintf("localhost:%d", 3001)
	listen, _ := net.Listen("tcp", endPoint)

	grpcServer := grpc.NewServer()

	hmacSecretPtr := flag.String("hmac", "", "a secret to sign the jwt")
	pathPtr := flag.String("path", "", "path to the policy file to use")
	enginePtr := flag.String("engine", "opa", "the policy engine to use [opa, cedar]")
	flag.Parse()

	if *pathPtr == "" {
		fmt.Println("requires --path value")
		return
	}

	if *hmacSecretPtr == "" {
		fmt.Println("requires --hmac value")
		return
	}

	var policyEngine policyengine.PolicyEngine
	switch *enginePtr {
	case "opa":
		policyEngine = &policyengine.OpaEngine{}
	case "cedar":
		policyEngine = &policyengine.OpaEngine{}
	default:
		fmt.Printf("unknown policy engine %s\n", *enginePtr)
		return
	}
	// load rego and keep watching for changes
	go internal.WatchFile(*pathPtr, policyEngine)

	// register envoy proto server
	server := &AuthServer{
		policyEngine: policyEngine,
		hmacSecret:   []byte(*hmacSecretPtr),
	}

	auth_pb.RegisterAuthorizationServer(grpcServer, server)

	fmt.Println("Server started at port 3001")
	grpcServer.Serve(listen)
}
