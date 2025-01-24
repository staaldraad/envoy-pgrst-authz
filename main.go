package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	auth_pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/v1/rego"
	"google.golang.org/grpc"
)

type AuthServer struct {
	pq rego.PreparedEvalQuery
}

type ParsedInput struct {
	Path       string   `json:"path"`
	Table      string   `json:"table"`
	Select     []string `json:"select"`
	Conditions string   `json:"conditions"`
}

type Allowed struct {
	Allowed bool   `json:"allow"`
	Reason  string `json:"reason,omitempty"`
}

func (server *AuthServer) Check(ctx context.Context, request *auth_pb.CheckRequest) (*auth_pb.CheckResponse, error) {
	// block if path is /private
	path := request.Attributes.Request.Http.Path[1:]

	parsedInput := ParsedInput{Path: path}
	query := strings.Split(path, "?")
	parsedInput.Table = query[0]
	if len(query) > 1 {
		// split path on `&`
		parts := strings.Split(query[1], "&")
		// find select
		for _, p := range parts {
			sp := strings.Split(p, "=")
			if len(sp) > 0 {
				switch sp[0] {
				case "select":
					parsedInput.Select = strings.Split(sp[1], ",")
				}
			}
		}
	}
	rs, err := server.pq.Eval(ctx, rego.EvalInput(parsedInput))
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("request not allowed")
	}

	if rs[0].Expressions[0].Value == false {
		fmt.Println("blocked private request")
		return nil, fmt.Errorf("request not allowed")
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

	ctx := context.Background()
	grpcServer := grpc.NewServer()

	// load rego
	authzFile, err := os.Open("auth.rego")
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
		return
	}

	// register envoy proto server
	server := &AuthServer{pq}
	auth_pb.RegisterAuthorizationServer(grpcServer, server)

	fmt.Println("Server started at port 3001")
	grpcServer.Serve(listen)
}
