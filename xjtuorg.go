package xjtuorg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
)

type XjtuOrg struct {
	client  http.Client
	headers http.Header
	crypter cipher.Block
}

func New(mobile bool) XjtuOrg {
	encrypter, err := aes.NewCipher([]byte("0725@pwdorgopenp"))
	if err != nil {
		panic("Crypto error")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic("Cookie jar creation failed")
	}
	ans := XjtuOrg{
		client:  http.Client{Jar: jar},
		headers: http.Header{},
		crypter: encrypter,
	}

	if mobile {
		ans.headers.Set("User-Agent", "Mozilla/5.0 (Linux; Android 14; 2211133C Build/UKQ1.230804.001; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/126.0.6478.134 Mobile Safari/537.36 toon/2123344193 toonType/150 toonVersion/6.4.0 toongine/1.0.12 toongineBuild/12 platform/android language/zh skin/white fontIndex/0")
		ans.headers.Set("X-Requested-With", "synjones.commerce.xjtu")
	} else {
		ans.headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	}
	return ans
}

func aesECBEncrypt(crypter cipher.Block, input []byte) []byte {
	// round up
	bs := crypter.BlockSize()
	align_size := (len(input) | (bs - 1)) + 1

	buf := make([]byte, align_size)
	copy(buf, input)
	// do ecb padding
	pad := byte(align_size - len(input))
	for i := len(input); i < align_size; i++ {
		buf[i] = pad
	}
	for i := 0; i < align_size; i += bs {
		crypter.Encrypt(buf[i:i+bs], buf[i:i+bs])
	}
	return buf
}

const Phase1Url = "https://org.xjtu.edu.cn/openplatform/g/admin/login"
const Phase2Url = "https://org.xjtu.edu.cn/openplatform/g/admin/getUserIdentity"
const Phase3Url = "https://org.xjtu.edu.cn/openplatform/oauth/auth/getRedirectUrl"

type LoginError int

const (
	RequestError LoginError = iota
	ApiError
	NoIdentity
)

func (t LoginError) Error() string {
	switch t {
	case RequestError:
		return "LoginError:RequestError"
	case ApiError:
		return "LoginError:ApiError"
	case NoIdentity:
		return "LoginError:NoIdentity"
	}
	panic("error not registered")
}

type GeneralResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type ContentType string

const (
	None ContentType = "none"
	Json ContentType = "application/json"
	Form ContentType = "application/x-www-form-urlencoded"
)

func (t *XjtuOrg) request(req *http.Request, content_type ContentType) (*GeneralResponse, error) {
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

	if res.StatusCode != 200 {
		return nil, RequestError
	}

	res_body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var res_json GeneralResponse
	err = json.Unmarshal(res_body, &res_json)
	if err != nil {
		return nil, err
	}
	if res_json.Code != 0 {
		return nil, ApiError
	}
	return &res_json, nil
}
func (t *XjtuOrg) Login(login_url, username, password string) (redir_url string, err error) {
	encrypted_passwd := aesECBEncrypt(t.crypter, []byte(password))
	encoded := base64.StdEncoding.EncodeToString(encrypted_passwd)

	// Phase 0: visit login page to retrieve cookies
	_, err = t.client.Get(login_url)
	if err != nil {
		return "", err
	}

	type LoginMessage struct {
		LoginType    int    `json:"loginType"`
		Username     string `json:"username"`
		Pwd          string `json:"pwd"`
		JcaptchaCode string `json:"jcaptchaCode"`
	}

	// Phase 1, post login credentials (with cookies) to API
	login_message := LoginMessage{
		LoginType:    1,
		Username:     username,
		Pwd:          encoded,
		JcaptchaCode: "",
	}
	post_data, err := json.Marshal(login_message)
	if err != nil {
		panic("Json encode failure")
	}

	req, err := http.NewRequest(http.MethodPost, Phase1Url, bytes.NewReader(post_data))
	if err != nil {
		return "", err
	}
	res_json, err := t.request(req, Json)
	if err != nil {
		return "", err
	}
	var res_data struct {
		OrgInfo struct {
			AddNew           int    `json:"addNew"`
			FirstLogin       int    `json:"firstLogin"`
			IsIdentification int    `json:"isIdentification"`
			Logo             string `json:"logo"`
			MemberId         int    `json:"memberId"`
			MemberName       string `json:"memberName"`
			OrgId            int    `json:"orgId"`
			OrgName          string `json:"orgName"`
		} `json:"orgInfo"`
		PwdState string `json:"pwdState"`
		State    string `json:"state"`
		TokenKey string `json:"tokenKey"`
	}
	err = mapstructure.Decode(res_json.Data, &res_data)
	if err != nil {
		return "", err
	}
	// set cookie according to response
	cookieMemberId := http.Cookie{
		Name:  "memberId",
		Value: strconv.Itoa(res_data.OrgInfo.MemberId),
	}
	cookieTokenKey := http.Cookie{
		Name:  "open_Platform_User",
		Value: res_data.TokenKey,
	}
	cookieState := http.Cookie{
		Name:  "state",
		Value: res_data.State,
	}
	base_url, err := url.Parse("https://org.xjtu.edu.cn/")
	if err != nil {
		panic("Url parse failed")
	}
	t.client.Jar.SetCookies(base_url, []*http.Cookie{&cookieMemberId, &cookieTokenKey, &cookieState})
	fmt.Println("[XJTU Authentication] Login successfully")

	// Phase 2: get user identity
	form := url.Values{}
	form.Add("memberId", strconv.Itoa(res_data.OrgInfo.MemberId))

	req, err = http.NewRequest(http.MethodPost, Phase2Url, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}

	res_json, err = t.request(req, Form)
	if err != nil {
		return "", err
	}
	type Identity struct {
		PersonNo                string `json:"personNo"`
		UserType                int    `json:"userType"`
		PayCard                 string `json:"payCard"`
		RailwayStationStart     string `json:"railwaystationstart"`
		RailwayStationStartName string `json:"railwaystationstartName"`
		RailwayStation          string `json:"railwaystation"`
		RailwayStationName      string `json:"railwaystationName"`
	}
	var identities []Identity

	err = mapstructure.Decode(res_json.Data, &identities)
	if err != nil {
		return "", err
	}
	// choose identity
	redir_param := make(url.Values)

	if len(identities) == 1 {
		redir_param.Add("userType", strconv.Itoa(identities[0].UserType))
		redir_param.Add("personNo", identities[0].PersonNo)
	} else {
		for _, identity := range identities {
			if identity.PersonNo == username {
				redir_param.Add("userType", strconv.Itoa(identity.UserType))
				redir_param.Add("personNo", identity.PersonNo)
				break
			}
		}
		if len(redir_param) == 0 {
			return "", NoIdentity
		}
	}
	now := time.Now()
	redir_param.Add("_", strconv.FormatInt(now.UTC().UnixMilli(), 10))
	fmt.Printf("[XJTU Authentication] Identity selected: %s\n", redir_param.Get("personNo"))

	req, err = http.NewRequest(http.MethodGet, Phase3Url+"?"+redir_param.Encode(), nil)
	if err != nil {
		return "", err
	}
	res_json, err = t.request(req, None)
	if err != nil {
		return "", err
	}
	redir_url = res_json.Data.(string)

	// Phase 0: visit login page to retrieve cookies
	_, err = t.client.Get(redir_url)
	if err != nil {
		return "", err
	}
	return redir_url, nil
}
