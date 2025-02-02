package policyengine

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	auth_pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/v1/rego"
)

type OpaEngine struct {
	preparedQuery rego.PreparedEvalQuery
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

func (oe *OpaEngine) AuthzRequest(ctx context.Context, request *auth_pb.CheckRequest, hmacSecret []byte) (ok bool, err error) {
	path := request.Attributes.Request.Http.Path[1:]
	parsedInput := parsePath(path)
	parsedInput.Method = extractSQLMethod(request.Attributes.Request.Http.Method, request.Attributes.Request.Http.Headers)
	parsedInput.Jwt = extractJWT(hmacSecret, request.Attributes.Request.Http.Headers)

	rs, err := oe.preparedQuery.Eval(ctx, rego.EvalInput(parsedInput))
	if err != nil {
		fmt.Println(err)
		return false, fmt.Errorf("request not allowed by exception")
	}

	if rs[0].Expressions[0].Value == false {
		fmt.Println("blocked request by policy")
		return false, nil
	}
	return true, nil
}

func parsePath(path string) ParsedInput {
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
	return parsedInput
}

func (oe *OpaEngine) LoadPolicy(rawPolicy []byte) (err error) {
	ctx := context.Background()
	r := rego.New(
		rego.Query("data.authz.allow"),
		rego.Module("authz.rego", string(rawPolicy)),
	)
	// Prepare for evaluation
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return err
	}
	oe.preparedQuery = pq
	return nil
}
