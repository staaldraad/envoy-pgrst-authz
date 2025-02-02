package policyengine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	cedar "github.com/cedar-policy/cedar-go"
	auth_pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

type CedarEngine struct {
	ps *cedar.PolicySet
}

type Entity struct {
	Uid     EntityDef              `json:"uid"`
	Attrs   map[string]interface{} `json:"attrs"`
	Parents []EntityDef            `json:"parents"`
}
type EntityDef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (ce *CedarEngine) AuthzRequest(ctx context.Context, request *auth_pb.CheckRequest, hmacSecret []byte) (ok bool, err error) { // takes a request and turns into the input expected by the policy engine

	if ce.ps == nil {
		// we don't have a valid policy set
		return true, nil
	}
	parsedInput := parsePath(hmacSecret, request.Attributes.Request)
	// convert to entities
	ents := make([]Entity, 4)

	id, hasJWT := parsedInput.Jwt["id"].(string)
	if !hasJWT {
		return true, nil
	}
	ents[0] = Entity{Uid: EntityDef{Type: "User", ID: id}, Attrs: parsedInput.Jwt}
	columns := make(map[string]interface{})
	columns["columns"] = parsedInput.Select
	filters := make(map[string]interface{})
	filters["filters"] = parsedInput.Filters
	ents[1] = Entity{Uid: EntityDef{Type: "Table", ID: parsedInput.Table}, Attrs: columns}
	ents[2] = Entity{Uid: EntityDef{Type: "Function", ID: parsedInput.Function}, Attrs: columns}
	ents[3] = Entity{Uid: EntityDef{Type: "Filters", ID: "filters"}, Attrs: filters}
	entitiesJSON, _ := json.Marshal(ents)

	var entities cedar.EntityMap
	if err := json.Unmarshal([]byte(entitiesJSON), &entities); err != nil {
		log.Fatal(err)
	}
	var resource cedar.EntityUID
	if parsedInput.Table != "" {
		resource = cedar.NewEntityUID("Table", cedar.String(parsedInput.Table))
	} else {
		resource = cedar.NewEntityUID("Function", cedar.String(parsedInput.Function))
	}
	req := cedar.Request{
		Principal: cedar.NewEntityUID("User", cedar.String(id)),
		Action:    cedar.NewEntityUID("Action", cedar.String(parsedInput.Method)),
		Resource:  resource,
		Context: cedar.NewRecord(cedar.RecordMap{
			"demoRequest": cedar.True,
		}),
	}

	if okk, diag := ce.ps.IsAuthorized(entities, req); !okk {
		if len(diag.Errors) > 0 {
			fmt.Println((diag.Errors))
			return false, nil
		}
		fmt.Println("blocked request by policy")
		return false, nil
	}
	return true, nil
}

func (ce *CedarEngine) LoadPolicy(rawPolicy []byte) error {

	if ps, err := cedar.NewPolicySetFromBytes("policy0", rawPolicy); err != nil {
		return err
	} else {
		ce.ps = ps
	}
	return nil
}
