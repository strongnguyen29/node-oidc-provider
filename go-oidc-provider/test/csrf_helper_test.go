package test

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"testing"
)

// csrfTokenRE matches the hidden CSRF input rendered into interaction and
// device-flow forms. The HTML renders the field as
//
//	<input type="hidden" name="csrf_token" value="...">
//
// so a relaxed regex is sufficient — there is no need to pull in a full HTML
// parser for tests.
var csrfTokenRE = regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`)

// fetchCSRFFromURL fetches an arbitrary URL that renders a form containing a
// csrf_token hidden field and returns the token value.
func fetchCSRFFromURL(t *testing.T, client *http.Client, url string) string {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("fetchCSRF: GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("fetchCSRF: read body: %v", err)
	}
	m := csrfTokenRE.FindSubmatch(body)
	if len(m) < 2 {
		t.Fatalf("fetchCSRF: csrf_token not found in %s body=%s", url, truncateForLog(string(body)))
	}
	return string(m[1])
}

// csrfForInteraction returns the CSRF token rendered for the named uid by
// fetching the interaction GET page.
func csrfForInteraction(t *testing.T, client *http.Client, base, uid string) string {
	t.Helper()
	return fetchCSRFFromURL(t, client, fmt.Sprintf("%s/interaction/%s", base, uid))
}

// csrfForDevice returns the CSRF token rendered into the device GET form.
func csrfForDevice(t *testing.T, client *http.Client, base string) string {
	t.Helper()
	return fetchCSRFFromURL(t, client, base+"/device")
}

func truncateForLog(s string) string {
	const lim = 200
	if len(s) <= lim {
		return s
	}
	return s[:lim] + "..."
}
