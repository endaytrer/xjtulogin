# XJTUORG

XJTU authentication module in Go

### Usage

```go
import (
	"net/http"
	"net/http/cookiejar"

    "github.com/endaytrer/xjtuorg"
)

// the parameter is whether to login as mobile
login_session := xjtuorg.New(true)

netid := "3124100000"
passwd := "password123"

// The login process would not begin before calling `Login`.
redir, err := login_session.Login("https://example.com/web/cas/login.html", netid, password)

if err != nil {
    // deal with error
}

// Now request with session to `redir`
client := http.Client{Jar: cookiejar.New(nil)}
_, err := client.Get(redir)

if err != nil {
    // deal with error
}

// Now you are logged in!
// Use `client` to make requests.
```