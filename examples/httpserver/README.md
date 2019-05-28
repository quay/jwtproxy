# HTTP Server

This example demonstrates authenticating a web service using jwtproxy.

```
client <--> signer proxy <--> verifier proxy <--> web service
```

Three components are deployed using the Procfile contained in this example folder:
- **A simple web server**: The web server provides a web service on which we want to add authentication.
- **A forward proxy**: Used by the web service clients, the proxy signs every requests to our web service by adding a JWT.
- **A reverse proxy**: The reverse proxy receives requests, validates JWTs and forwards the requests to the web server.

### Pre-requisites

To run this example, you need [Go] and a working [Go environment] and [goreman].

[Go 1.6]: https://github.com/golang/go/releases
[Go environment]: https://golang.org/doc/code.html
[goreman]: https://github.com/mattn/goreman

### Configuration

For the sake of simplicity, this example uses a pre-shared key pair to sign and verify the requests. Two configuration files are used, one for the signer and one for the verifier, respectively `signer.yaml` and `verifier.yaml`. It is recommended that you inspect them to understand how jwtproxy works.

### Run

Simply execute the Procfile:

```
goreman start
```

### Test

Using curl, we send a request for the web service to the verifier proxy address. The verifier proxy will verify the authentication token and forward it upon success to our web service. We also specify that a forward proxy has to be used - it will sign our requests.

```
curl --proxy localhost:3128 http://localhost:8080/
```

### Learn more

Extensive documentation can be found in the [README].
To learn more about the different configuration parameters, you may read [config.example.yaml].

[README]: ../../README.md
[config.example.yaml]: ../../config.example.yaml
