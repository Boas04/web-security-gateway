// Internal Coraza inspection service. Never stores raw requests or rule match text.
package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	crs "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

type envelope struct {
	Method  string            `json:"method"`
	URI     string            `json:"uri"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Client  string            `json:"client"`
}
type verdict struct {
	Allowed bool  `json:"allowed"`
	Rules   []int `json:"rules"`
}

func newWAF() (coraza.WAF, error) {
	// Bundled upstream recommended parsing rules + OWASP CRS. No raw audit/debug output.
	return coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(crs.FS).
		WithErrorCallback(func(types.MatchedRule) {}).
		WithDirectives(`
Include @coraza.conf-recommended
SecRuleEngine On
SecAuditEngine Off
SecDebugLogLevel 0
SecRequestBodyLimit 16384
SecRequestBodyInMemoryLimit 16384
SecRequestBodyLimitAction Reject
SecResponseBodyAccess Off
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
`))
}

func inspect(waf coraza.WAF, input envelope) (verdict, error) {
	result := verdict{Rules: []int{}}
	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessConnection(input.Client, 0, "127.0.0.1", 8081)
	tx.ProcessURI(input.URI, input.Method, "HTTP/1.1")
	parsed, err := url.ParseRequestURI(input.URI)
	if err != nil {
		return result, err
	}
	// Coraza 3.8 separates URI parsing from population of GET arguments.
	arguments, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return result, err // Never inspect only a partial query and forward the rest.
	}
	for key, values := range arguments {
		for _, value := range values {
			tx.AddGetRequestArgument(key, value)
		}
	}
	for key, value := range input.Headers {
		tx.AddRequestHeader(key, value)
	}
	tx.SetServerName(input.Headers["Host"])
	interruption := tx.ProcessRequestHeaders()
	if interruption == nil {
		body, decodeErr := base64.StdEncoding.DecodeString(input.Body)
		if decodeErr != nil {
			return result, decodeErr
		}
		interruption, _, err = tx.WriteRequestBody(body)
		if err != nil {
			return result, err
		}
		if interruption == nil {
			interruption, err = tx.ProcessRequestBody()
			if err != nil {
				return result, err
			}
		}
	}
	seen := map[int]bool{}
	for _, match := range tx.MatchedRules() {
		id := match.Rule().ID()
		if !seen[id] {
			result.Rules = append(result.Rules, id)
			seen[id] = true
		}
	}
	sort.Ints(result.Rules)
	result.Allowed = interruption == nil
	// Do not serialize MatchedRules themselves: messages/data can contain secrets.
	return result, nil
}

func handler(waf coraza.WAF) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/inspect" {
			http.NotFound(w, r)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			w.WriteHeader(415)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var input envelope
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || len(input.URI) > 8192 || len(input.Headers) > 100 || !strings.HasPrefix(input.URI, "/") || strings.HasPrefix(input.URI, "//") {
			w.WriteHeader(400)
			return
		}
		result, err := inspect(waf, input)
		if err != nil {
			w.WriteHeader(503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
}

func main() {
	waf, err := newWAF()
	if err != nil {
		log.Fatal("WAF initialization failed; verify pinned rules/configuration")
	}
	address := os.Getenv("LISTEN")
	if address == "" {
		address = ":8081"
	}
	server := &http.Server{Addr: address, Handler: handler(waf), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	log.Print("Coraza inspection service ready; raw logging disabled")
	if server.ListenAndServe() != http.ErrServerClosed {
		log.Fatal("Inspection listener stopped")
	}
}
