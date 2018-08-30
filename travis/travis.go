package travis

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	statusSuccess = 0
	//statusNotSuccess = 1

	payloadKey = "payload"
)

func NewHandler(onReceive func(*Webhook), onError func(error)) http.HandlerFunc {
	if onReceive == nil {
		onReceive = func(w *Webhook) {}
	}

	if onError == nil {
		onError = func(e error) {}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		err := validateSignature(r)
		if err != nil {
			onError(err)
			return
		}

		payload := new(Webhook)
		err = json.Unmarshal([]byte(r.FormValue(payloadKey)), payload)
		if err != nil {
			onError(err)
			return
		}
		payload.Success = payload.Status == statusSuccess

		go onReceive(payload)
		return
	}
}

const (
	publicConfURL  = "https://api.travis-ci.org/config"
	privateConfURL = "https://api.travis-ci.com/config"
)

func publicKey(publicTravis bool) (*rsa.PublicKey, error) {
	var url string
	if publicTravis {
		url = publicConfURL
	} else {
		url = privateConfURL
	}

	response, err := http.Get(url)
	if err != nil {
		return nil, errors.New("cannot fetch travis public key")
	}
	defer response.Body.Close()

	type configKey struct {
		Config struct {
			Notifications struct {
				Webhook struct {
					PublicKey string `json:"public_key"`
				} `json:"webhook"`
			} `json:"notifications"`
		} `json:"config"`
	}

	var t configKey

	decoder := json.NewDecoder(response.Body)
	err = decoder.Decode(&t)
	if err != nil {
		return nil, errors.New("cannot decode travis public key")
	}

	keyBlock, _ := pem.Decode([]byte(t.Config.Notifications.Webhook.PublicKey))
	if keyBlock == nil || keyBlock.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid travis public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		return nil, errors.New("invalid travis public key")
	}

	return publicKey.(*rsa.PublicKey), nil
}

func payloadDigest(payload string) []byte {
	hash := sha1.New()
	n, err := hash.Write([]byte(payload))
	if err != nil || n != len([]byte(payload)) {
		panic("digest failed")
	}
	return hash.Sum(nil)
}

func validateSignature(r *http.Request) error {
	isPub, err := isPublic(r)
	if err != nil {
		return err
	}

	key, err := publicKey(isPub)
	if err != nil {
		return err
	}

	signature, err := base64.StdEncoding.DecodeString(r.Header.Get("Signature"))
	if err != nil {
		return errors.New("cannot decode signature")
	}

	payload := payloadDigest(r.FormValue(payloadKey))

	err = rsa.VerifyPKCS1v15(key, crypto.SHA1, payload, signature)
	if err != nil {
		if err == rsa.ErrVerification {
			return errors.New("invalid payload signature")
		}
		return err
	}

	return nil
}

func isPublic(r *http.Request) (bool, error) {
	var p struct {
		BuildURL string `json:"build_url"`
	}
	err := json.Unmarshal([]byte(r.FormValue(payloadKey)), &p)
	if err != nil {
		return false, err
	}

	return strings.HasPrefix(p.BuildURL, "https://travis-ci.org"), nil // .org = public, .com = private
}

type Webhook struct {
	Success bool `json:-`

	ID                int       `json:"id"`
	Number            string    `json:"number"`
	Type              string    `json:"type"`
	State             string    `json:"state"`
	Status            int       `json:"status"` // status and result are the same
	Result            int       `json:"result"`
	StatusMessage     string    `json:"status_message"` // status_message and result_message are the same
	ResultMessage     string    `json:"result_message"`
	StartedAt         time.Time `json:"started_at"`
	FinishedAt        time.Time `json:"finished_at"`
	Duration          int       `json:"duration"`
	BuildURL          string    `json:"build_url"`
	CommitID          int       `json:"commit_id"`
	Commit            string    `json:"commit"`
	BaseCommit        string    `json:"base_commit"`
	HeadCommit        string    `json:"head_commit"`
	Branch            string    `json:"branch"`
	Message           string    `json:"message"`
	CompareURL        string    `json:"compare_url"`
	CommittedAt       time.Time `json:"committed_at"`
	AuthorName        string    `json:"author_name"`
	AuthorEmail       string    `json:"author_email"`
	CommitterName     string    `json:"committer_name"`
	CommitterEmail    string    `json:"committer_email"`
	PullRequest       bool      `json:"pull_request"`
	PullRequestNumber int       `json:"pull_request_number"`
	PullRequestTitle  string    `json:"pull_request_title"`
	Tag               string    `json:"tag"`
	Repository        struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		OwnerName string `json:"owner_name"`
		URL       string `json:"url"`
	} `json:"repository"`
}
