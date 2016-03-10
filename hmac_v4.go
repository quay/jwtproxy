// Copyright 2016 CoreOS, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hmacproxy

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client/metadata"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/private/signer/v4"

	"github.com/coreos-inc/hmacproxy/credential"
)

// timeFormat is the format used in the X-Amz-Date header with aws-sdk-go.
const timeFormat = "20060102T150405Z"

var (
	// ErrNoValidSignature is returned when the http.Request that's being verified doesn't contain
	// a valid signature.
	ErrNoValidSignature = errors.New("could not verify http request: no valid signature")

	// ErrSignatureMismatch is returned when the http.Request's signature is different than the one
	// that has been computed.
	ErrSignatureMismatch = errors.New("could not verify http request: signature mismatch")

	// ErrSignatureTooSkewed is returned when the http.Request that's being verified hasn't been
	// signed within the `maxSkew` window. This limits the possibility that intercepted requests could
	// be replayed by an adversary.
	ErrSignatureTooSkewed = errors.New("could not verify http request: signature too skewed")

	// WhiteListedHeaders is the list of http.Header that are explicitely excluded during signature
	// verifications.
	WhiteListedHeaders = map[string]struct{}{
		"X-Amz-Date":           {},
		"X-Amz-Content-Sha256": {},
		"Authorization":        {},
		"Accept-Encoding":      {},
	}

	// signatureRegexp matches the HMAC signature and captures its key ID, service and region names.
	signatureRegexp = regexp.MustCompile(`AWS4-HMAC-SHA256\s+Credential=([^\/]+)\/(?:[^\/]+)\/([^\/]+)\/([^\/]+)\/aws4_request,\s+SignedHeaders=(?:[^;]+;)+[^,]+,\s+Signature=[0-9a-f]+`)
)

// Sign4 signs the given http.Request using AWS-Style HMAC v4
// with the specified Credential, region and service names.
func Sign4(req *http.Request, cred credential.Credential) error {
	// If the request that we need to sign has a Body, we must read it entirely and convert it into a
	// ReadSeeker in order to sign the request.
	if req.Body != nil {
		body, err := newReadSeekCloser(req.Body)
		if err != nil {
			return err
		}

		req.Body = body
	}

	// Sign the given http.Request.
	return sign(req, cred.ID, cred.Secret, cred.Region, cred.Service, time.Now().UTC())
}

// Verify4 verifies the AWS-Style HMAC v4 signature present in the given http.Request.
// It uses the CredentialStore to find the appropriate Credential based on the key ID, region and
// service names. The maxSkew duration represents the time window within a signed request stays
// valid. Verify4 returns the Credential that has been used to sign the request or nil if the
// http.Request could not be verified successfully. An error is also returned and indicates the
// failure reason.
func Verify4(req *http.Request, creds credential.Store, maxSkew time.Duration) (*credential.Credential, error) {
	// Shallow copy the request as we're going to modify its headers,
	// and make its Body a ReadSeekerCloser as AWS going to read it and http.Request must be able to
	// Close() it.
	reqCopy, err := duplicateRequest(req)
	if err != nil {
		return nil, err
	}

	// Assign the Host properly to match the initial signed request.
	reqCopy.URL.Host = reqCopy.Host

	// Extract the signature and signature time out of the request's headers.
	signature := reqCopy.Header.Get("Authorization")
	signatureTime, errT := time.Parse(timeFormat, reqCopy.Header.Get("X-Amz-Date"))

	// Extract the key ID, service and region names out of the signature.
	keyID, serviceName, regionName, errP := parseSignature(signature)

	// Ensure that the given request has a valid signature, otherwise we can't verify anything.
	if signature == "" || errP != nil || errT != nil {
		return nil, ErrNoValidSignature
	}

	// Get the Credential associated with the key ID, service and region names from the
	// CredentialStore.
	cred, err := creds.LoadCredential(keyID, serviceName, regionName)
	if err != nil {
		return nil, err
	}

	// Remove any potential white-listed headers fron the incoming request.
	for header := range reqCopy.Header {
		if _, isWhitelisted := WhiteListedHeaders[header]; isWhitelisted {
			reqCopy.Header.Del(header)
		}
	}

	// Sign our copy of the given http.Request.
	err = sign(reqCopy, keyID, cred.Secret, regionName, serviceName, signatureTime)
	if err != nil {
		return nil, err
	}

	// Compare the computed signature with the one that's present in the request that we're verifying.
	computedSignature := reqCopy.Header.Get("Authorization")
	if subtle.ConstantTimeCompare([]byte(signature), []byte(computedSignature)) != 1 {
		return nil, ErrSignatureMismatch
	}

	// Compare the signature date with the skew policy.
	if signatureTime.After(time.Now().UTC().Add(maxSkew)) ||
		signatureTime.Before(time.Now().UTC().Add(-maxSkew)) {
		return nil, ErrSignatureTooSkewed
	}

	return cred, nil
}

// parseSignature extracts the key ID, the service name and the region name out of the given
// signature or an error if the signature's format is invalid.
func parseSignature(signature string) (string, string, string, error) {
	m := signatureRegexp.FindStringSubmatch(signature)
	if m == nil {
		return "", "", "", errors.New("invalid signature format")
	}

	return m[0], m[1], m[2], nil
}

func sign(req *http.Request, keyID, keySecret, regionName, serviceName string, time time.Time) error {
	// Forge an AWS request.
	awsReq := &request.Request{
		Config: aws.Config{
			Credentials: credentials.NewStaticCredentials(keyID, keySecret, ""),
			Region:      aws.String(regionName),
		},
		ClientInfo: metadata.ClientInfo{
			ServiceName: serviceName,
		},
		Time:        time,
		HTTPRequest: req,
		Body:        req.Body.(io.ReadSeeker),
	}

	// Sign the request.
	v4.Sign(awsReq)

	if awsReq.Error != nil {
		return awsReq.Error
	}
	return nil
}

// ReadSeekCloser regroups the io.Reader, io.Seeker, and io.Closer interfaces.
type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

type readSeekNopCloser struct {
	io.ReadSeeker
}

func (r readSeekNopCloser) Close() error {
	return nil
}

// duplicateRequest shallows copy the given http.Request and returns the copy.
// However, because we don't need the modify the Body but only read it twice (once for verifying the
// signature and once by whoever uses it), the Body is shared between the two objects, but
// implements Seeker. AWS is going to seek it back to offset 0.
func duplicateRequest(req *http.Request) (*http.Request, error) {
	reqCopy := &http.Request{}
	*reqCopy = *req

	body, err := newReadSeekCloser(req.Body)
	if err != nil {
		return reqCopy, err
	}
	req.Body = body
	reqCopy.Body = body

	reqCopy.Header = make(http.Header, len(req.Header))
	for k, s := range req.Header {
		reqCopy.Header[k] = append([]string(nil), s...)
	}

	return reqCopy, nil
}

// newReadSeekCloser instantiates a ReadSeekCloser from a io.ReadCloser.
// Note that it breaks any kind of streaming as it reads the given reader entirely (and closes it)
// in order to make it seekable.
func newReadSeekCloser(r io.ReadCloser) (ReadSeekCloser, error) {
	if r == nil {
		return nil, nil
	}

	buffer, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	r.Close()

	return readSeekNopCloser{bytes.NewReader(buffer)}, nil
}
