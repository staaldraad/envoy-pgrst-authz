package policyengine

import (
	"context"
	"fmt"

	auth_pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/v1/rego"
)

type OpaEngine struct {
	preparedQuery rego.PreparedEvalQuery
}

func (oe *OpaEngine) Init() error {
	return nil
}

func (oe *OpaEngine) AuthzRequest(ctx context.Context, request *auth_pb.CheckRequest, hmacSecret []byte) (ok bool, err error) {
	parsedInput := parsePath(hmacSecret, request.Attributes.Request)
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
