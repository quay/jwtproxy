package keyregistry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-oidc/key"
	"github.com/pmylund/go-cache"
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
	cache        *cache.Cache
	registry     *url.URL
	signerParams config.SignerParams
}

type Config struct {
	Registry config.URL `yaml:"registry"`
}

type ManagerConfig struct {
	Config `yaml:",inline"'`
	Cache  *CacheConfig `yaml:"cache"`
}

type CacheConfig struct {
	Duration      time.Duration `yaml:"duration"`
	PurgeInterval time.Duration `yaml:"purge_interval"`
}

func (krc *Client) GetPublicKey(issuer string, keyID string) (*key.PublicKey, error) {
	// Query cache for public key.
	if krc.cache != nil {
		if cpk, found := krc.cache.Get(issuer + keyID); found {
			pk := cpk.(key.PublicKey)
			return &pk, nil
		}
	}

	// Query key registry for a public key matching the given issuer and key ID.
	resp, err := http.Get(krc.absURL("services", issuer, "keys", keyID).String())
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, keyserver.ErrPublicKeyNotFound
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"Unexpected response code when looking for public key: got status code %d, expected 200",
			resp.StatusCode,
		)
	}

	defer resp.Body.Close()

	// Decode the public key we received as a JSON-encoded JWK.
	var pk key.PublicKey
	jsonDecoder := json.NewDecoder(resp.Body)
	err = jsonDecoder.Decode(&pk)
	if err != nil {
		return nil, err
	}

	// Cache the public key.
	if krc.cache != nil {
		krc.cache.Set(issuer+keyID, pk, cache.DefaultExpiration)
	}

	return &pk, nil
}

func (krc *Client) PublishPublicKey(key *key.PublicKey, policy *keyserver.KeyPolicy, signingKey *key.PrivateKey) *keyserver.PublishResult {
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
		publishURL := krc.absURL("services", krc.signerParams.Issuer, "keys", key.ID())

		queryParams := publishURL.Query()
		if policy.Expiration != nil {
			log.Debug("Adding expiration time: ", policy.Expiration)
			queryParams.Add("expiration", strconv.FormatInt(policy.Expiration.Unix(), 10))
		}
		if policy.RotationPolicy != nil {
			log.Debug("Adding rotation time: ", policy.RotationPolicy)
			queryParams.Add("rotation", strconv.Itoa(int(policy.RotationPolicy.Seconds())))
		}
		publishURL.RawQuery = queryParams.Encode()

		resp, err := krc.signAndDo("PUT", publishURL, bytes.NewReader(body), signingKey)
		if err != nil {
			publishResult.SetError(err)
			return
		}

		switch resp.StatusCode {
		case http.StatusOK:
			// Published successfully.
			publishResult.Success()
			return
		case http.StatusAccepted:
			monPublishLog := log.WithFields(log.Fields{
				"keyID":        key.ID()[0:10],
				"signingKeyID": signingKey.ID()[0:10],
			})

			// Our key couldn't be published immediately because it requires
			// approval. Loop until it becomes approved or the whole process
			// gets canceled.
			monPublishLog.Debug("Monitoring publish status")
			monURL := krc.absURL("services", krc.signerParams.Issuer, "keys", key.ID())

			pollPeriod := time.NewTicker(1 * time.Second)
			defer pollPeriod.Stop()

			for {
				select {
				case <-pollPeriod.C:
					checkPublished, err := krc.signAndDo("GET", monURL, nil, signingKey)
					if err != nil {
						publishResult.SetError(err)
						return
					}

					switch checkPublished.StatusCode {
					case http.StatusOK:
						publishResult.Success()
						return
					case http.StatusConflict:
						monPublishLog.Debug("Key not yet approved, waiting")
					default:
						checkPublishedErr := fmt.Errorf(
							"Unexpected response code when checking approval status %d",
							checkPublished.StatusCode,
						)
						publishResult.SetError(checkPublishedErr)
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
			publishServerError := fmt.Errorf(
				"Unexpected response code when publishing key: %d ",
				resp.StatusCode,
			)
			publishResult.SetError(publishServerError)
			return
		}
	}()

	return publishResult
}

func (krc *Client) DeletePublicKey(keyID string, signingKey *key.PrivateKey) error {
	url := krc.absURL("services", krc.signerParams.Issuer, "keys", keyID)

	resp, err := krc.signAndDo("DELETE", url, nil, signingKey)
	if err != nil {
		return err
	}

	if resp.StatusCode != 204 {
		return fmt.Errorf("Unexpected response code when deleting public key: %d", resp.StatusCode)
	}

	return nil
}

func (krc *Client) Stop() {

}

func (krc *Client) signAndDo(method string, url *url.URL, body io.Reader, signingKey *key.PrivateKey) (*http.Response, error) {
	// Create an HTTP request to the key server to publish a new key.
	req, err := http.NewRequest(method, url.String(), body)
	if err != nil {
		return nil, err
	}

	if method == "PUT" || method == "POST" {
		req.Header.Add("Content-Type", "application/json")
	}

	// Sign it with the specified private key and config.
	err = jwt.Sign(req, signingKey, krc.signerParams)
	if err != nil {
		return nil, err
	}

	// Execute the request, if it returns a 200, close the channel immediately.
	return http.DefaultClient.Do(req)
}

func (krc *Client) absURL(pathParams ...string) *url.URL {
	escaped := make([]string, 0, len(pathParams)+1)
	escaped = append(escaped, krc.registry.Path)
	for _, pathParam := range pathParams {
		escaped = append(escaped, url.QueryEscape(pathParam))
	}

	absPath := path.Join(escaped...)
	relurl, err := url.Parse(absPath)
	if err != nil {
		panic(err)
	}
	return krc.registry.ResolveReference(relurl)
}

func constructReader(registrableComponentConfig config.RegistrableComponentConfig) (keyserver.Reader, error) {
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}

	return &Client{
		registry: cfg.Registry.URL,
	}, nil
}

func constructManager(registrableComponentConfig config.RegistrableComponentConfig, signerParams config.SignerParams) (keyserver.Manager, error) {
	bytes, err := yaml.Marshal(registrableComponentConfig.Options)
	if err != nil {
		return nil, err
	}
	var cfg ManagerConfig
	err = yaml.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil, err
	}

	// Initialize a cache if configured.
	var c *cache.Cache
	if cfg.Cache != nil {
		if cfg.Cache.Duration == 0 {
			log.Warning("Key registry is configured to cache public keys but no expiration has been set. This could lead to memory outage.")
		} else if cfg.Cache.Duration > 0 && cfg.Cache.PurgeInterval <= 0 {
			return nil, errors.New("Key registry is configured to cache public keys, which have an expiration time, but no purge interval has been set.")
		}

		c = cache.New(cfg.Cache.Duration, cfg.Cache.PurgeInterval)
	} else {
		log.Warning("Key registry is not configured to use a cache. This could introduce undesired latency during signature verification.")
	}

	return &Client{
		registry:     cfg.Registry.URL,
		cache:        c,
		signerParams: signerParams,
	}, nil
}
