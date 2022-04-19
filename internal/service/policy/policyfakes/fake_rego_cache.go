// Code generated by counterfeiter. DO NOT EDIT.
package policyfakes

import (
	"sync"

	"code.vereign.com/gaiax/tsa/policy/internal/service/policy"
	"github.com/open-policy-agent/opa/rego"
)

type FakeRegoCache struct {
	GetStub        func(string) (*rego.PreparedEvalQuery, bool)
	getMutex       sync.RWMutex
	getArgsForCall []struct {
		arg1 string
	}
	getReturns struct {
		result1 *rego.PreparedEvalQuery
		result2 bool
	}
	getReturnsOnCall map[int]struct {
		result1 *rego.PreparedEvalQuery
		result2 bool
	}
	SetStub        func(string, *rego.PreparedEvalQuery)
	setMutex       sync.RWMutex
	setArgsForCall []struct {
		arg1 string
		arg2 *rego.PreparedEvalQuery
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeRegoCache) Get(arg1 string) (*rego.PreparedEvalQuery, bool) {
	fake.getMutex.Lock()
	ret, specificReturn := fake.getReturnsOnCall[len(fake.getArgsForCall)]
	fake.getArgsForCall = append(fake.getArgsForCall, struct {
		arg1 string
	}{arg1})
	stub := fake.GetStub
	fakeReturns := fake.getReturns
	fake.recordInvocation("Get", []interface{}{arg1})
	fake.getMutex.Unlock()
	if stub != nil {
		return stub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *FakeRegoCache) GetCallCount() int {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	return len(fake.getArgsForCall)
}

func (fake *FakeRegoCache) GetCalls(stub func(string) (*rego.PreparedEvalQuery, bool)) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = stub
}

func (fake *FakeRegoCache) GetArgsForCall(i int) string {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	argsForCall := fake.getArgsForCall[i]
	return argsForCall.arg1
}

func (fake *FakeRegoCache) GetReturns(result1 *rego.PreparedEvalQuery, result2 bool) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = nil
	fake.getReturns = struct {
		result1 *rego.PreparedEvalQuery
		result2 bool
	}{result1, result2}
}

func (fake *FakeRegoCache) GetReturnsOnCall(i int, result1 *rego.PreparedEvalQuery, result2 bool) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = nil
	if fake.getReturnsOnCall == nil {
		fake.getReturnsOnCall = make(map[int]struct {
			result1 *rego.PreparedEvalQuery
			result2 bool
		})
	}
	fake.getReturnsOnCall[i] = struct {
		result1 *rego.PreparedEvalQuery
		result2 bool
	}{result1, result2}
}

func (fake *FakeRegoCache) Set(arg1 string, arg2 *rego.PreparedEvalQuery) {
	fake.setMutex.Lock()
	fake.setArgsForCall = append(fake.setArgsForCall, struct {
		arg1 string
		arg2 *rego.PreparedEvalQuery
	}{arg1, arg2})
	stub := fake.SetStub
	fake.recordInvocation("Set", []interface{}{arg1, arg2})
	fake.setMutex.Unlock()
	if stub != nil {
		fake.SetStub(arg1, arg2)
	}
}

func (fake *FakeRegoCache) SetCallCount() int {
	fake.setMutex.RLock()
	defer fake.setMutex.RUnlock()
	return len(fake.setArgsForCall)
}

func (fake *FakeRegoCache) SetCalls(stub func(string, *rego.PreparedEvalQuery)) {
	fake.setMutex.Lock()
	defer fake.setMutex.Unlock()
	fake.SetStub = stub
}

func (fake *FakeRegoCache) SetArgsForCall(i int) (string, *rego.PreparedEvalQuery) {
	fake.setMutex.RLock()
	defer fake.setMutex.RUnlock()
	argsForCall := fake.setArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *FakeRegoCache) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	fake.setMutex.RLock()
	defer fake.setMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeRegoCache) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ policy.RegoCache = new(FakeRegoCache)
