# Authenticated nginx server on Kubernetes

This example demonstrates authenticating an nginx server using jwtproxy on Kubernetes.

In this example, we will deploy a pod that contains a unexposed nginx server and a verifier proxy, exposed on the port 80. Because the nginx server is unexposed, the only way to access it externally (i.e. outside the pod) is to go through the reverse proxy, which enforce authentication by validating JWTs. A service will also be created to enable external access (i.e. outside the cluster) to the service.

### Pre-requisites

To run this example, you need a working [Kubernetes] cluster.


For the sake of simplicity, this example uses a pre-shared key pair to sign and verify the requests.

[Kubernetes]: http://kubernetes.io/

### Deploy

First of all, we create two Kubernetes secrets:
- **secret-nginx-config**: Contains an nginx virtual host configuration file to make our web server listen on port 8080 (in the pod only) and serve a static response,
- **secret-jwtproxy-config**: Contains the verifier proxy configuration that will listen on port 80 (externally), verify requests' authentication and forward them to nginx.

```
$ kubectl create secret generic secret-nginx-config --from-file nginx.conf
$ kubectl create secret generic secret-verifier-config --from-file verifier.yaml --from-file mykey.pub
```

And then, we deploy the pod and service that expose our secured web service:

```
$ kubectl create -f nginx-app.yaml
```

### Test

To demonstrate a bit further, we'll deploy a second pod that will send requests to our web service at regular intervals, via a signer proxy that will provide authentication.

```
$ kubectl create secret generic secret-tester-config --from-file signer.yaml --from-file mykey.key
$ kubectl create -f tester-app.yaml
```

As soon as the pod is deployed, we can watch the logs and read the responses to our authenticated requests.

```
$ kubectl logs -f tester tester
Welcome to this authenticated web service.
Welcome to this authenticated web service.
Welcome to this authenticated web service.
```

### Learn more

Extensive documentation can be found in the [README].
To learn more about the different configuration parameters, you may read [config.example.yaml].

[README]: ../../README
[config.example.yaml]: ../../config.example.yaml
