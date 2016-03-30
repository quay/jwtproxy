package keyregistry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/key"
	"gopkg.in/yaml.v2"

	"github.com/coreos-inc/jwtproxy/config"
	"github.com/coreos-inc/jwtproxy/jwt"
	"github.com/coreos-inc/jwtproxy/jwt/keyserver"
)

func init() {
	keyserver.RegisterReader("keyregistry", constructReader)
	keyserver.RegisterManager("keyregistry", constructManager)
}

type Client struct {
	Registry     *url.URL
	SignerParams config.SignerParams
}

type Config struct {
	Registry config.URL `yaml:"registry"`
}

func (krc *Client) GetPublicKey(issuer string, keyID string) (*key.PublicKey, error) {
	resp, err := http.Get(krc.absURL("services", issuer, "keys", keyID))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, keyserver.ErrPublicKeyNotFound
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Unexpected response code when looking for public key: got status code %d, expected 200", resp.StatusCode)
	}

	defer resp.Body.Close()
	jsonDecoder := json.NewDecoder(resp.Body)
	var pk key.PublicKey

	err = jsonDecoder.Decode(&pk)
	if err != nil {
		return nil, err
	}

	return &pk, nil
}

func (krc *Client) PublishPublicKey(key *key.PublicKey, signingKey *key.PrivateKey) *keyserver.PublishResult {
	// Create a channel that will track the response status.
	publishResult := keyserver.NewPublishResult()

	go func() {
		// Serialize the jwk as the body.
		body, err := json.Marshal(key)
		if err != nil {
			publishResult.SetError(err)
			return
		}

		// Create an HTTP request to the key server to publish a new key.
		url := krc.absURL("services", krc.SignerParams.Issuer, "keys", key.ID())
		resp, err := krc.signAndDo("PUT", url, bytes.NewReader(body), signingKey)
		if err != nil {
			publishResult.SetError(err)
			return
		}

		// If it returns a 202, fire up a goroute to poll for when the key has been
		// accepted and close the channel when it has.
		switch resp.StatusCode {
		case 200:
			// Published successfully.
			publishResult.Success()
			return
		case 202:
			monPublishLog := log.WithFields(log.Fields{
				"keyID":        key.ID(),
				"signingKeyID": signingKey.ID(),
			})

			// Our key couldn't be published immediately because it requires
			// approval. Fire up a goroutine to watch whether it becomes
			// published.
			monPublishLog.Debug("Monitoring publish status")

			pollPeriod := time.NewTicker(1 * time.Second)
			defer pollPeriod.Stop()

			// TODO read this from the 202 response headers.
			expirationTime := time.Now().Add(30 * time.Minute)
			for {
				select {
				case <-pollPeriod.C:
					checkPublished, err := krc.signAndDo("GET", url, nil, signingKey)
					if err != nil {
						publishResult.SetError(err)
						return
					}

					switch checkPublished.StatusCode {
					case 200:
						publishResult.Success()
						return
					case 404:
						monPublishLog.Debug("Key not yet published, waiting")
					default:
						checkPublishedErr := fmt.Errorf("Unexpected response code when checking publication status %d", checkPublished.StatusCode)
						publishResult.SetError(checkPublishedErr)
						return
					}

					if time.Now().After(expirationTime) {
						timedOutErr := fmt.Errorf("Key publication timed out before success")
						publishResult.SetError(timedOutErr)
						return
					}

				case <-publishResult.WaitForCancel():
					monPublishLog.Debug("Canceling key publication monitor goroutine")
					canceledErr := fmt.Errorf("Key publication monitor canceled")
					publishResult.SetError(canceledErr)
					pollPeriod.Stop()
					return
				}
			}

		default:
			publishServerError := fmt.Errorf("Unexpected response code when publishing key: %d ", resp.StatusCode)
			publishResult.SetError(publishServerError)
			return
		}
	}()

	return publishResult
}

func (krc *Client) DeletePublicKey(keyID string, signingKey *key.PrivateKey) error {
	url := krc.absURL("services", krc.SignerParams.Issuer, "keys", keyID)

	resp, err := krc.signAndDo("DELETE", url, nil, signingKey)
	if err != nil {
		return err
	}

	if resp.StatusCode != 204 {
		return fmt.Errorf("Unexpected response code when deleting public key: %d", resp.StatusCode)
	}

	return nil
}

func (krc *Client) signAndDo(method, url string, body io.Reader, signingKey *key.PrivateKey) (*http.Response, error) {
	// Create an HTTP request to the key server to publish a new key.
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	if method == "PUT" || method == "POST" {
		req.Header.Add("Content-Type", "application/json")
	}

	// Sign it with the specified private key and config.
	err = jwt.Sign(req, signingKey, krc.SignerParams)
	if err != nil {
		return nil, err
	}

	// Execute the request, if it returns a 200, close the channel immediately.
	return http.DefaultClient.Do(req)
}

func (krc *Client) absURL(pathParams ...string) string {
	escaped := make([]string, 0, len(pathParams)+1)
	escaped = append(escaped, krc.Registry.Path)
	for _, pathParam := range pathParams {
		escaped = append(escaped, url.QueryEscape(pathParam))
	}

	absPath := path.Join(escaped...)
	relurl, err := url.Parse(absPath)
	if err != nil {
		panic(err)
	}
	return krc.Registry.ResolveReference(relurl).String()
}

func constructor(registrableComponentConfig config.RegistrableComponentConfig) (*Client, error) {
	var cfg Config
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}
	return &Client{
		Registry: cfg.Registry.URL,
	}, nil
}

func constructReader(registrableComponentConfig config.RegistrableComponentConfig) (keyserver.Reader, error) {
	return constructor(registrableComponentConfig)
}

func constructManager(registrableComponentConfig config.RegistrableComponentConfig, signerParams config.SignerParams) (keyserver.Manager, error) {
	manager, err := constructor(registrableComponentConfig)
	manager.SignerParams = signerParams
	return manager, err
}
