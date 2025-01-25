package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
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

	parsedInput := parsePath(path)

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

func parsePath(path string) ParsedInput {
	parsedInput := ParsedInput{Path: path}
	u, _ := url.Parse(path)
	query := u.Query()
	parsedInput.Table = u.Path
	for q, p := range query {
		switch q {
		case "select":
			parsedInput.Select = strings.Split(p[0], ",")
		}
	}
	return parsedInput
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
