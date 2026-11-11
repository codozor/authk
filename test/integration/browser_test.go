//go:build integration

package integration

import (
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// insecureJar keeps the cookies Keycloak marks Secure over http://localhost: a browser
// accepts them (localhost is a secure context), Go's cookiejar drops them.
type insecureJar struct{ *cookiejar.Jar }

func (j insecureJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		c.Secure = false
	}
	j.Jar.SetCookies(u, cookies)
}

// browser is a minimal user agent filling the Keycloak login pages.
type browser struct {
	client *http.Client
}

func newBrowser() *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{client: &http.Client{Jar: insecureJar{jar}, Timeout: 30 * time.Second}}
}

var (
	formRe   = regexp.MustCompile(`(?s)<form[^>]*\baction="([^"]*)"[^>]*>(.*?)</form>`)
	inputRe  = regexp.MustCompile(`<input[^>]*>`)
	attrRe   = regexp.MustCompile(`\b(name|value|type)="([^"]*)"`)
	buttonRe = regexp.MustCompile(`<(?:button|input)\b[^>]*>`)
	titleRe  = regexp.MustCompile(`(?s)<h1[^>]*>(.*?)</h1>`)
)

type page struct {
	url  *url.URL
	body string
}

func (b *browser) get(u string) (*page, error) {
	resp, err := b.client.Get(u)
	if err != nil {
		return nil, err
	}
	return readPage(resp)
}

func (b *browser) post(u string, form url.Values) (*page, error) {
	resp, err := b.client.PostForm(u, form)
	if err != nil {
		return nil, err
	}
	return readPage(resp)
}

func readPage(resp *http.Response) (*page, error) {
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &page{url: resp.Request.URL, body: string(body)}, nil
}

func (p *page) title() string {
	m := titleRe.FindStringSubmatch(p.body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(m[1]))
}

// form returns the action and the fields of the first form of the page.
func (p *page) form() (string, url.Values, bool) {
	m := formRe.FindStringSubmatch(p.body)
	if m == nil {
		return "", nil, false
	}
	action, err := p.url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		return "", nil, false
	}
	fields := url.Values{}
	for _, in := range inputRe.FindAllString(m[2], -1) {
		attrs := map[string]string{}
		for _, a := range attrRe.FindAllStringSubmatch(in, -1) {
			attrs[a[1]] = html.UnescapeString(a[2])
		}
		if attrs["name"] != "" && attrs["type"] != "submit" {
			fields.Set(attrs["name"], attrs["value"])
		}
	}
	return action.String(), fields, true
}

// buttons returns the named submit buttons of the page: name → value (attributes in
// any order; a button without value gets "on").
func (p *page) buttons() map[string]string {
	b := map[string]string{}
	for _, tag := range buttonRe.FindAllString(p.body, -1) {
		attrs := map[string]string{}
		for _, a := range attrRe.FindAllStringSubmatch(tag, -1) {
			attrs[a[1]] = html.UnescapeString(a[2])
		}
		isButton := strings.HasPrefix(tag, "<button")
		if attrs["name"] == "" || (!isButton && attrs["type"] != "submit") {
			continue
		}
		if attrs["value"] == "" {
			attrs["value"] = "on"
		}
		b[attrs["name"]] = attrs["value"]
	}
	return b
}

func (p *page) String() string {
	return fmt.Sprintf("%s (%q)", p.url, p.title())
}

var errUnexpectedPage = errors.New("unexpected page")

// login logs in as alice from a login URL shown by authk: the device verification URL
// (with the code) or the authorization URL, which ends on the local callback of authk.
func login(loginURL string) error {
	b := newBrowser()
	p, err := b.get(loginURL)
	if err != nil {
		return err
	}
	for range 5 {
		if p.url.Hostname() == "127.0.0.1" || strings.Contains(p.title(), "Device Login Successful") {
			return nil
		}
		action, fields, ok := p.form()
		switch {
		case !ok:
			return fmt.Errorf("%w: %s", errUnexpectedPage, p)
		case fields.Has("username"):
			fields.Set("username", "alice")
			fields.Set("password", "alice-password")
		case p.buttons()["accept"] != "":
			fields.Set("accept", p.buttons()["accept"])
		default:
			return fmt.Errorf("%w: %s, buttons %v, fields %v", errUnexpectedPage, p, p.buttons(), fields)
		}
		if p, err = b.post(action, fields); err != nil {
			return err
		}
	}
	return fmt.Errorf("%w: still not logged in at %s", errUnexpectedPage, p)
}
