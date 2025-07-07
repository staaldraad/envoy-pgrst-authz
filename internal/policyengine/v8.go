package policyengine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"time"

	auth_pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/jackc/puddle"
	"github.com/tommie/v8go"
)

type V8Engine struct {
	CompiledScript *v8go.UnboundScript
	RawScript      []byte
	IsolatePool    *puddle.Pool
}

func (v8e *V8Engine) Init() error {
	// create an isolates pool to allow multiple isolates
	// to be pre created. This avoids cold starts and keeps
	// script execution fast
	maxPoolSize := int32(runtime.NumCPU())
	constructor := func(context.Context) (any, error) {
		iso := v8go.NewIsolate()
		return iso, nil // creates a new JVM
	}
	destructor := func(value any) {
		value.(*v8go.Isolate).Dispose() // clean things up, release memory
	}

	v8e.IsolatePool = puddle.NewPool(constructor, destructor, maxPoolSize)
	return nil
}

func (v8e *V8Engine) AuthzRequest(ctx context.Context, request *auth_pb.CheckRequest, hmacSecret []byte) (ok bool, err error) {
	parsedInput := parsePath(hmacSecret, request.Attributes.Request)
	start := time.Now()

	// get an isolate from the IsolatePool
	// res, _ := v8e.IsolatePool.Acquire(context.Background())
	// defer res.Release() // should always release the isolate back to the pool
	// iso := res.Value().(*v8go.Isolate)
	iso := v8go.NewIsolate()
	defer iso.Dispose()
	v8ctx := v8go.NewContext(iso)
	if v8ctx == nil {
		fmt.Printf("unable to create context for request")
		return false, fmt.Errorf("unable to create context for request")
	}
	defer v8ctx.Close()

	//should use the precompiled script to save some time, but scripts should be so small
	// that this doesn't really matter. Also using compiled cache seems to cause memory greater
	// memory usage when not using per request isolates
	// scripts must be compiled by isolate
	//script, err := iso.CompileUnboundScript(string(v8e.RawScript), "customEngine.js", v8go.CompileOptions{CachedData: &v8go.CompilerCachedData{Bytes: v8e.CompiledScript.Bytes}})
	_, err = v8ctx.RunScript(string(v8e.RawScript), "customEngine.js")
	// if err != nil {
	// 	return false, fmt.Errorf("no valid v8 script compiled")
	// }
	// if using compileUnboundScript
	// script.Run(v8ctx)
	fng, err := v8ctx.Global().Get("handleRequest")
	if err != nil {
		fmt.Printf("Unable to find handleRequest, check your script: %v", err)
		return false, fmt.Errorf("Unable to find handleRequest, check your script", err)
	}
	fn, err := fng.AsFunction()
	if err != nil {
		fmt.Printf("Unable to find handleRequest, check your script %v", err)
		return false, fmt.Errorf("Unable to find handleRequest, check your script", err)
	}

	jsonBytes, err := json.Marshal(parsedInput)
	if err != nil {
		log.Fatal(err)
	}
	// Parse the JSON string into a V8 object using JSON.parse
	jsonParseScript := fmt.Sprintf("JSON.parse(%q)", string(jsonBytes))
	v8Obj, err := v8ctx.RunScript(jsonParseScript, "parse.js")
	if err != nil {
		log.Fatal(err)
	}
	result, err := fn.Call(fng, v8Obj)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(time.Since(start))
	return result.Boolean(), nil
}

/* LoadPolicy(rawPolicy []byte)
 * recompiles the v8 script using a compile isolate
 * the compiled script is cached to make future execution faster
 */
func (v8e *V8Engine) LoadPolicy(rawPolicy []byte) (err error) {
	iso := v8go.NewIsolate()
	defer iso.Dispose()
	script, err := iso.CompileUnboundScript(string(rawPolicy), "customEngine.js", v8go.CompileOptions{})
	if err != nil {
		return err
	}
	v8e.CompiledScript = script
	v8e.RawScript = rawPolicy
	return nil
}
