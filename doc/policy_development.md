# Policy Development Extensions

The policy service extends the standard Rego runtime with custom 
built-in functions and some custom functionalities described here.

### Pure Evaluation Results

In the Rego language there is a blank identifier variable which 
can be used for assignments. If used like it's shown below, the
result from the policy evaluation will not be embedded in variable, 
but will be returned as *pure* result. 

> This is custom functionality developed in the policy service
> and is not standard behaviour of the OPA Rego runtime.

Below are two examples for what it means.

If the following policy is evaluated, the returned result will be 
*embedded* in an attribute named `credential`:

```
package example.createProof

credential := proof.create(input)
```

Result:
```json
{
    "credential": {
        "@context": "...",
        "type": "VerifiableCredential",
        "credentialSubject": {...},
        "proof": {...}
    }
}
```

If however a blank identifier is used for the assignment, the result 
of the policy evaluation won't be embedded in an attribute named
`credential` but will be returned directly:

```
package example.createProof

_ := proof.create(input)
```

Result:
```json
{
    "@context": "...",
    "type": "VerifiableCredential",
    "credentialSubject": {...},
    "proof": {...}
}
```

A policy developer can use the blank identifier assignment to skip the
mapping of a function call to a JSON attribute name. The result of the 
function call will be returned directly as JSON. 

This is useful in case you want to return a DID document or Verifiable Credential
from policy evaluation, and the document must not be mapped to an upper level attribute.

### Extension Functions

A number of Rego extension functions are developed and injected in the
policy service Rego runtime. Here is a list with brief description for
each one of them.

#### cache.get

The function retrieves JSON data from the Cache service. It accepts
three parameters used to identify the underlying Cache key. Only the
first one named `key` is required, the other two may be empty.

Example:
```
package example.cacheGet

data := cache.get("mykey", "", "")
```

#### cache.set

The function inserts JSON data into the Cache service. It accepts
four parameters. First three are used to identify/construct the 
underlying Cache key. The last one is the data to be stored.

Example:
```
package example.cacheSet

result := cache.set("mykey", "", "", input.data)
```

#### did.resolve

Resolve DID using the [Universal DID Resolver](https://github.com/decentralized-identity/universal-resolver)
and return the resolved DID document. 

Example:
```
package example.didResolve

result := did.resolve("did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6")
```

#### task.create

Start asynchronous task and pass the given data as task input. The function accepts two
parameters: task name and the input data.

Example:
```
package example.taskCreate

result := task.create("task-name", input.data)
```

#### tasklist.create

Start asynchronous task list and pass the given data as input. The function accepts two
parameters: task list name and the input data.   

Example:
```
package example.tasklist

result := tasklist.create("task-list-name", input.data)
```

#### keys.get

Retrieve a specific public key from the signer service. The function accepts one
argument which is the name of the key. The key is returned in JWK format
wrapped in a DID verification method envelope.

Example:
```
package example.getkey

_ := keys.get("key1")
```

Result:
```json
{
  "id": "key1",
  "publicKeyJwk": {
    "crv": "P-256",
    "kid": "key1",
    "kty": "EC",
    "x": "RTx_2cyYcGVSIRP_826S32BiZxSgnzyXgRYmKP8N2l0",
    "y": "unnPzMAnbByBMq2l9WWKsDFE-MDvX6hYhrESsjAaT50"
  },
  "type": "JsonWebKey2020"
}
```

#### keys.getAll

Retrieve all public keys from the signer service. The result is JSON array of
keys in JWK format wrapped in a DID verification method envelope.

Example:
```
package example.getAllKeys

_ := keys.getAll()
```

Result:
```json
[
  {
    "id": "key1",
    "publicKeyJwk": {
      "crv": "P-256",
      "kid": "key1",
      "kty": "EC",
      "x": "RTx_2cyYcGVSIRP_826S32BiZxSgnzyXgRYmKP8N2l0",
      "y": "unnPzMAnbByBMq2l9WWKsDFE-MDvX6hYhrESsjAaT50"
    },
    "type": "JsonWebKey2020"
  },
  {
    ...
  }
]
```

#### issuer

Retrieve DID issuer value configured in the signer service.

Example:
```
package example.getIssuer

did := issuer().did
```

Result:
```json
{
  "did": "did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6"
}
```

#### proof.create

Create a proof for Verifiable Credential or Verifiable Presentation.
The function accepts one argument which represents a VC or VP in JSON format.
It calls the signer service to generate a proof and returns the response, 
which is the same VC/VP but with proof section. 

Example Policy:
```
package example.createProof

_ := proof.create(input)
```

Example VC given to policy evaluation:
```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "credentialSubject": {
    "allow": true,
    "id": "example/examplePolicy/1.0"
  },
  "issuanceDate": "2022-07-12T13:59:35.246990412Z",
  "issuer": "did:web:gaiax.vereign.com:tsa:policy:policy:example:returnDID:1.0:evaluation",
  "type": "VerifiableCredential"
}
```

Example Response:
```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "credentialSubject": {
    "allow": true,
    "id": "example/examplePolicy/1.0"
  },
  "issuanceDate": "2022-07-12T13:59:35.246990412Z",
  "issuer": "did:web:gaiax.vereign.com:tsa:policy:policy:example:returnDID:1.0:evaluation",
  "proof": {
    "created": "2022-07-21T09:57:37.761706653Z",
    "jws": "eyJhbGciOiJKc29uV2ViU2lnbmF0dXJlMjAyMCIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..MEUCIQCOuTbwqembXOv2wjPhPkjR5Minf27DhO_KbNmXdxRxKQIgK3DTaucbir5SYNi_5Xwj8mpKoXxoKzF5_ZYUJB98IBE",
    "proofPurpose": "assertionMethod",
    "type": "JsonWebSignature2020",
    "verificationMethod": "did:web:gaiax.vereign.com:tsa:policy:policy:example:returnDID:1.0:evaluation#key1"
  },
  "type": "VerifiableCredential"
}
```

#### proof.verify

Verify a proof for Verifiable Credential or Verifiable Presentation.
The function accepts one argument which represents a VC or VP in JSON format.
It calls the signer service to validate the proof.

Example Policy:
```
package example.verifyProof

valid := proof.verify(input)
```

Example VC given to policy evaluation:
```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "credentialSubject": {
    "allow": true,
    "id": "example/examplePolicy/1.0"
  },
  "issuanceDate": "2022-07-12T13:59:35.246990412Z",
  "issuer": "did:web:gaiax.vereign.com:tsa:policy:policy:example:returnDID:1.0:evaluation",
  "proof": {
    "created": "2022-07-21T09:57:37.761706653Z",
    "jws": "eyJhbGciOiJKc29uV2ViU2lnbmF0dXJlMjAyMCIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..MEUCIQCOuTbwqembXOv2wjPhPkjR5Minf27DhO_KbNmXdxRxKQIgK3DTaucbir5SYNi_5Xwj8mpKoXxoKzF5_ZYUJB98IBE",
    "proofPurpose": "assertionMethod",
    "type": "JsonWebSignature2020",
    "verificationMethod": "did:web:gaiax.vereign.com:tsa:policy:policy:example:returnDID:1.0:evaluation#key1"
  },
  "type": "VerifiableCredential"
}
```

Result:
```json
{
  "valid": true
}
```
