package storage

// Temporary hardcoded policy storage as a simple map.
// When we finalize with Steffen how we're going to store
// and synchronize policy files, this will be replaced with
// real policy store.
//var policies = map[string]*Policy{
//	"example:example:1.0": {
//		Filename:   "example_1.0.rego",
//		Name:       "example",
//		Group:      "example",
//		Version:    "1.0",
//		Locked:     false,
//		LastUpdate: time.Now(),
//		Rego: `
//			package example.example
//
//			abc := "hello world"
//
//			allow {
//				abc == "hello world"
//			}
//
//			taskID := "deadbeef"
//		`,
//	},
//}
