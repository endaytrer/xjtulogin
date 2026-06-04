# XJTULogin

XJTU authentication module in Go

### How login.xjtu.edu.cn Work

Below is the request flow implemented in [xjtulogin.go](xjtulogin.go). It lists every REST call, payload shape, and the expected response handling.

1. Fetch RSA public key

    - `GET https://login.xjtu.edu.cn/cas/jwt/publicKey`
    - Response body: PEM-encoded RSA public key (string)
    - Client action: encrypt the raw password with RSA PKCS#1 v1.5, then Base64 encode it.

2. Load login page and extract execution token

    - `GET {login_url}` (the CAS login page you want to authenticate against)
    - Response body: HTML login page
    - Client action: parse HTML and read the hidden input `#fm1 > input[name="execution"]`.

3. Detect MFA requirement

    - `POST https://login.xjtu.edu.cn/cas/mfa/detect`
    - Content-Type: `application/x-www-form-urlencoded`
    - Body fields:
        - `loginType=passwordLogin`
        - `username={username}`
        - `password=__RSA__{base64_rsa_password}`
        - `fpVisitorId={visitor_id}` (16-byte random hex string)
    - Response JSON (wrapped): `{"code":0,"data":{...}}`
    - Client action:
        - If `code != 0`: treat as API error.
        - If `data.need == false`: go to step 6 (no MFA).
        - If `data.need == true`: go to step 4 (MFA required).

4. Initialize MFA (secure phone)

    - `GET https://login.xjtu.edu.cn/cas/mfa/initByType/securephone?state={mfa_state}`
    - Response JSON (wrapped): `{"code":0,"data":{"gid":"...","securePhone":"..."}}`
    - Client action: save `gid`, `securePhone`, and the MFA `state` for OTP flow.

5. OTP flow (only when MFA is required)

    1. Send OTP
        - `POST https://login.xjtu.edu.cn/attest/api/guard/securephone/send`
        - Content-Type: `application/json`
        - Body: `{"gid":"{gid}"}`
        - Response JSON (wrapped): `{"code":0,"data":{"result":"ok"}}`
        - Client action: if `code != 0` or `result != "ok"`, treat as API error.

    2. Validate OTP
        - `POST https://login.xjtu.edu.cn/attest/api/guard/securephone/valid`
        - Content-Type: `application/json`
        - Body: `{"code":"{otp}","gid":"{gid}"}`
        - Response JSON (wrapped): `{"code":0,"data":{"result":"ok","status":1}}`
        - Client action: if `code != 0` or `result != "ok"`, treat as API error.

6. Submit login form

    - `POST {postLoginUrl}` (returned by the CAS login page)
    - Content-Type: `application/x-www-form-urlencoded`
    - Body fields:
        - `username={username}`
        - `password=__RSA__{base64_rsa_password}`
        - `captcha=`
        - `currentMenu=1`
        - `failN=0`
        - `mfaState={mfa_state}`
        - `execution={execution}`
        - `_eventId=submit`
        - `geolocation=`
        - `fpVisitorId={visitor_id}`
        - `trustAgent=true|""` (based on user choice)
        - `submit1=Login1`
    - Expected response:
        - `302 Found` with a `Location` header for redirection.
        - The client allows redirects only while the host is one of:
          `org.xjtu.edu.cn`, `login.xjtu.edu.cn`, `identity1.xjtu.edu.cn`.
        - The first 302 to another host is treated as success, and the `Location` URL is returned.
        - Any non-302 (except a handled 401) is treated as a failure.


### Usage

See [example](./example/main.go)