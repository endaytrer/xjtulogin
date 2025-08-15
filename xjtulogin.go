package xjtulogin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

// encryptWithPublicKey encrypts a message using RSA-OAEP.
func encryptWithPublicKey(message []byte, publicKeyPEM string) (string, error) {
	// 1. Decode the PEM block to get the raw DER-encoded key
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block containing public key")
	}

	// 2. Parse the DER-encoded public key
	// We use ParsePKIXPublicKey which is a common format for public keys.
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse DER encoded public key: %w", err)
	}

	// 3. Type-assert the parsed key to an RSA public key.
	// This is crucial to access RSA-specific methods.
	rsaPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("key is not a valid RSA public key")
	}

	// 4. Encrypt the message using RSA-PKCS1v15.
	// PKCS1v15 is an older padding scheme but still widely used.
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPubKey, message)
	if err != nil {
		return "", fmt.Errorf("error encrypting message: %w", err)
	}

	// 5. Return the ciphertext as a Base64-encoded string for easy transport.
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

type LoginForm struct {
	Username    string
	Password    string
	Captcha     string
	CurrentMenu string
	FailN       string
	MfaState    string
	Execution   string
	EventId     string
	GeoLocation string
	FpVisitorId string
	TrustAgent  string
	Submit1     string
}

func (f *LoginForm) Encode() []byte {
	ans := ""
	ans += "username=" + url.QueryEscape(f.Username) + "&"
	ans += "password=" + url.QueryEscape(f.Password) + "&"
	ans += "captcha=" + url.QueryEscape(f.Captcha) + "&"
	ans += "currentMenu=" + url.QueryEscape(f.CurrentMenu) + "&"
	ans += "failN=" + url.QueryEscape(f.FailN) + "&"
	ans += "mfaState=" + url.QueryEscape(f.MfaState) + "&"
	ans += "execution=" + url.QueryEscape(f.Execution) + "&"
	ans += "_eventId=" + url.QueryEscape(f.EventId) + "&"
	ans += "geolocation=" + url.QueryEscape(f.GeoLocation) + "&"
	ans += "fpVisitorId=" + url.QueryEscape(f.FpVisitorId) + "&"
	ans += "trustAgent=" + url.QueryEscape(f.TrustAgent) + "&"
	ans += "submit1=" + url.QueryEscape(f.Submit1)
	return []byte(ans)
}

func NewLoginForm(username, password, execution, visitor_id string) *LoginForm {
	return &LoginForm{
		Username:    username,
		Password:    fmt.Sprintf("__RSA__%s", password),
		Captcha:     "",
		CurrentMenu: "1",
		FailN:       "0",
		MfaState:    "",
		Execution:   execution,
		EventId:     "submit",
		GeoLocation: "",
		FpVisitorId: visitor_id,
		TrustAgent:  "",
		Submit1:     "Login1",
	}
}

type XjtuLogin struct {
	client  http.Client
	headers http.Header
}

func new(mobile bool) XjtuLogin {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic("Cookie jar creation failed: " + err.Error())
	}
	ans := XjtuLogin{
		client:  http.Client{Jar: jar},
		headers: make(http.Header),
	}
	if mobile {
		ans.headers.Set("User-Agent", "Mozilla/5.0 (Linux; Android 14; 2211133C Build/UKQ1.230804.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.6478.134 Mobile Safari/537.36 toon/2123344193 toonType/150 toonVersion/6.4.0 toongine/1.0.12 toongineBuild/12 platform/android language/zh skin/white fontIndex/0")
		ans.headers.Set("X-Requested-With", "synjones.commerce.xjtu")
	} else {
		ans.headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	}
	return ans
}

type ContentType string

const (
	None ContentType = "none"
	Json ContentType = "application/json"
	Form ContentType = "application/x-www-form-urlencoded"
)

type LoginError int

const (
	RequestError LoginError = iota
	ApiError
	NoIdentity
	UnknownError
)

func (t LoginError) Error() string {
	switch t {
	case RequestError:
		return "LoginError:RequestError"
	case ApiError:
		return "LoginError:ApiError"
	case NoIdentity:
		return "LoginError:NoIdentity"
	case UnknownError:
		return "LoginError:UnknownError"
	}
	panic("error not registered")
}

func (t *XjtuLogin) request(req *http.Request, content_type ContentType) (*http.Response, error) {
	req.Header = make(http.Header)
	for k, v := range t.headers {
		req.Header[k] = v
	}
	if content_type != None {
		req.Header.Add("Content-Type", string(content_type))
	}

	res, err := t.client.Do(req)

	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusFound {
		return nil, RequestError
	}
	return res, nil
}

func getAttribute(node *html.Node, key string) string {
	for _, attr := range node.Attr {
		if attr.Key == key {
			return attr.Val
		}
	}
	return ""
}

const PUBKEY_URL = "https://login.xjtu.edu.cn/cas/jwt/publicKey"

var selector_execution = cascadia.MustCompile("#fm1>input[name=\"execution\"]")

func (t *XjtuLogin) login(login_url, username, password string) (redir_url string, err error) {
	// phase one: get public key

	pubkey_resp, err := t.client.Get(PUBKEY_URL)
	if err != nil {
		return "", err
	}
	pubkey, err := io.ReadAll(pubkey_resp.Body)
	if err != nil {
		return "", err
	}
	// encrypt password with pubkey
	ciphertext, err := encryptWithPublicKey([]byte(password), string(pubkey))
	if err != nil {
		return "", err
	}
	login_page_req, err := http.NewRequest(http.MethodGet, login_url, nil)
	if err != nil {
		return "", err
	}
	login_page_resp, err := t.request(login_page_req, None)
	if err != nil {
		return "", err
	}
	post_login_url := login_page_resp.Request.URL
	login_page, err := html.Parse(login_page_resp.Body)
	if err != nil {
		return "", err
	}

	execution_input := cascadia.Query(login_page, selector_execution)
	execution := getAttribute(execution_input, "value")
	// generate a 32-character(16 byte) hexadecimal visitor_id
	var buf [16]byte
	rand.Read(buf[:])
	visitor_id := hex.EncodeToString(buf[:])
	login_form := NewLoginForm(username, ciphertext, execution, visitor_id)
	req, err := http.NewRequest(http.MethodPost, post_login_url.String(), strings.NewReader(string(login_form.Encode())))
	if err != nil {
		return "", err
	}
	t.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.Response.StatusCode != http.StatusFound {
			return nil
		}
		location, err := req.Response.Location()
		// 302 should have a location
		if err != nil {
			return err
		}
		if strings.Contains(location.String(), "org.xjtu.edu.cn") || strings.Contains(location.String(), "login.xjtu.edu.cn") {
			return nil
		}
		return http.ErrUseLastResponse
	}

	final_resp, err := t.request(req, Form)
	if err != nil {
		return "", err
	}
	if final_resp.StatusCode == http.StatusUnauthorized {
		return "", ApiError
	}
	if final_resp.StatusCode != http.StatusFound {
		return "", UnknownError
	}
	redir, err := final_resp.Location()
	if err != nil {
		return "", err
	}
	return redir.String(), nil
}

func Login(login_url, username, password string) (redir_url string, err error) {
	session := new(false)
	return session.login(login_url, username, password)
}
