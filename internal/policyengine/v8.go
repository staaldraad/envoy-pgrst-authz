package policyengine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime"
	"time"

	auth_pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/tommie/v8go"
)

type V8Engine struct {
	CompiledScript *v8go.UnboundScript
	RawScript      []byte
	//IsolatePool    *puddle.Pool
	Config      PoliceEngineConfig
	IsolatePool *IsolatePool
}

type IsolatePool struct {
	pool chan *PooledIsolate
}

type PooledIsolate struct {
	Isolate  *v8go.Isolate
	UseCount int
}

func NewIsolatePool(size int) *IsolatePool {
	pool := make(chan *PooledIsolate, size)

	for range size {
		iso := v8go.NewIsolate()
		pool <- &PooledIsolate{Isolate: iso, UseCount: 0}
	}

	return &IsolatePool{pool: pool}
}

func (ip *IsolatePool) Acquire() *PooledIsolate {
	piso := <-ip.pool
	piso.UseCount++
	return piso
}
func (ip *IsolatePool) Release(piso *PooledIsolate) {
	if piso.UseCount > 5 {
		// dispose of the isolate and create a new one
		piso.Isolate.Dispose()
		iso := v8go.NewIsolate()
		ip.pool <- &PooledIsolate{Isolate: iso, UseCount: 0}
	} else {
		ip.pool <- piso // return it
	}

}

func (v8e *V8Engine) Init(config PoliceEngineConfig) error {
	v8e.Config = config
	if config.UsePool {
		// create an isolates pool to allow multiple isolates
		// to be pre created. This avoids cold starts and keeps
		// script execution fast
		maxPoolSize := int32(runtime.NumCPU())
		v8e.IsolatePool = NewIsolatePool(runtime.NumCPU())
		fmt.Printf("V8 Engine intialised with pool of %d Isolates\n", maxPoolSize)
	}
	return nil
}

func (v8e *V8Engine) AuthzRequest(ctx context.Context, request *auth_pb.CheckRequest, hmacSecret []byte) (ok bool, err error) {
	parsedInput := parsePath(hmacSecret, request.Attributes.Request)
	start := time.Now()
	var iso *v8go.Isolate

	if v8e.Config.UsePool {
		// get an isolate from the IsolatePool
		piso := v8e.IsolatePool.Acquire()
		iso = piso.Isolate
		defer v8e.IsolatePool.Release(piso) // return it
	} else {
		iso = v8go.NewIsolate()
		defer iso.Dispose()
	}

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
