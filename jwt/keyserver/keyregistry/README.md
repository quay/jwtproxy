# Key Server Specification

This document covers what exactly it means for a server to be JWK public keys registry compliant. This is intended as an extension to the [JWK set spec](https://tools.ietf.org/html/rfc7517#section-5). 

## Terminology
| Term | Definition |
|---|---|
| private key | The private half of an asymmetric key which can be used to generate unforgeable signatures. |
| public key | The public half of an asymmetric key which can be shared and is used to verify a signature made with a private key. |
| key id | (**kid**) A unique opaque string which is used to refer to a key by name. This is often implemented as a fingerprint of the key. |
| issuer | (**iss**) An isssuer is the entity responsible for minting and signing a JWT. In JWK key server parlance, this is the holder of the private key. |
| service | This is synonymous with issuer for JWT purposes, but is made more generic in the key server routes |

## Operations

The following operations can be performed against the specified endpoints of a JWK key server compliant server.

### List All Public Keys for a Service

```
GET /services/<service_name>/keys
```

Example response:

```
200 OK

{
  keys: [
    { 
      <JWK contents>
    },
    {
      <JWK contents>
    }   
  ]
}
```

This call is guaranteed to always return a response, even if the service is unknown.

### Fetch a Single Public Key by ID

```
GET /services/<service_name>/keys/<key_id>
```

Response if they key is **published and approved**:

```
200 OK

Cache-Control: max-age=<cache time in seconds>

{
  <JWK content>
}
```

Response if the key was published but **awaiting approval**:

```
409 Conflict
```

Response if the key was previously approved, but is now **expired**:

```
403 Forbidden
```

Response if the key is **unknown**:

```
404 Unknown
```

### Publish a New Public Key for a Service

Publishing a new JWK requires that the request be authorized by a signed JWT. The server requires that the key id be specified as a `kid` JWT header, and that the `iss` issuer claim match the `<service_name>`. If this is a brand new key, the request must be self-signed (i.e. the JWT signature was made by the private key for which we're attempting to publish a public key). If this is a key rotation request, the request must be signed by a key which appears in the key list for this service (i.e. is currently approved and unexpired).

The optional argument `expiration` specifies the [unix time](https://en.wikipedia.org/wiki/Unix_time) as an integer number of seconds since the epoch at which time the key will expire.

The optional argument `rotation` is for guidance only, and specifies the anticipated amount of time as an integer number of seconds between key rotations. A key server can use this value to determine if an origin server missed a rotation request, and therefore may be unhealthy.

**NOTE:** Successfully rotating a key revokes the key that we signed the rotation request with when successful.

```
PUT /services/<service_name>/keys/<key_id>[?expiration=<timestamp>[&rotation=<seconds>]]

Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ

{
  <JWK contents>
}
```

Response when a **new key** is published and **requires approval**:

```
202 Accepted
```

Response when an **existing key** is successfully **replaced**:

```
200 OK
```

Response when the request is signed with an **inappropriate key**:

```
403 Forbidden
```

All other failures are interpreted as client errors:

```
400 Bad Request
```

### Revoke a Published Key

**NOTE:** There is no cache invalidation or revocation list mechanism in place. There are no guarantees that a revoked key will not be interpreted as successful by clients with a cached copy of the key until the key finally expires.

Revoking a public key requires that the request be authorized with a JWT which was signed by the key being revoked.

```
DELETE /services/<service_name>/keys/<key_id>
```

Response when the key is **successfully revoked**:

```
204 No Content
```

Response when the request is not properly self signed:

```
403 Forbidden
```

All other failures are interpreted as client errors:

```
400 Bad Request
```

## Client Use Cases

There are two primary ways that we intend the key server to be used. In the verifier use case, we use the key server to validate a request that we've already received. In the manager use case, we autogenerate a key, publish it, and then autorotate it on a schedule.

### Verifier

This is how the client is expected to use the key server to verify the origin of a JWT:

1. Receive a request signed with a JWT
2. Extract the `kid` JWT header
3. Extract the `iss` issuer claim from the JWT body
4. Fetch the public key from `/services/<iss>/keys/<kid>`
	* If the public key is unknown, the request fails
5. Use the public key to verify the signature on the JWT
	* If the signature does not validate with the public key, the request fails 

### Manager

This is roughly how a client can use the publish and fetch endpoints to publish and autorotate a key:

1. Generate a new public/private key pair
2. Serialize the public portion as a JWK
3. Generate a JWT, setting all of the strict jwt claims:
	* `iss`: our own service issuer name
	* `aud`: the scheme and hostname of the key server, e.g. `https://mykeyserver.com`
	* `exp`: an expiration time a short while from now, but not too short
	* `iat`: the time at which the JWT was generated
	* `nbf`: a short time in the past to accommodate clock skew
4. Sign the JWT with the private portion of our new key pair
5. Set the `kid` claim in our JWT headers to be the opaque ID string for our new key
6. `PUT /services/<iss>/keys/<kid>` -> 202
7. Poll `GET /services/<iss>/keys/<kid>` until 409 responses turn into 200
8. Our key is now published and approved

Rotating a key:

1. Generate a new public/priate key pair
2. Follow the steps above to create a JWT with the required claims
3. Sign the JWT with the private portion of our **previously approved and still active key**
4. `PUT /services/<iss>/keys/<kid>` -> 200
5. Our new key is now active, and our previous key is revoked.
