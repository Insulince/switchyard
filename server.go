package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// server is the dashboard, and it is the one thing that OUTLIVES a reload.
//
// That is the whole reason it is separate from the coordinator. Saving a
// config tears down every listener, every upstream session and the coordinator
// itself; if the HTTP server went with them, the page would lose the response
// to its own save and the operator would be staring at a dead tab wondering
// whether it worked. So the server holds the current coordinator behind a lock
// and swaps it as reloads happen.
type server struct {
	mu   sync.RWMutex
	co   *coordinator
	cfg  config
	path string

	// reloadC carries a request to rebuild everything from the file on disk.
	// Buffered by one: two saves arriving together should collapse into one
	// rebuild, not queue a second teardown behind the first.
	reloadC chan struct{}

	// lastErr is the reason the most recent reload failed, if it did. A
	// config can only get here having been validated, so this is almost
	// always a bind failure -- a port taken between the probe and the listen.
	lastErr string

	srv  *http.Server
	addr string
}

func newServer(path string) *server {
	return &server{path: path, reloadC: make(chan struct{}, 1)}
}

// swap installs a newly built coordinator. Called once at boot and once per
// successful reload.
func (s *server) swap(co *coordinator, cfg config) {
	s.mu.Lock()
	s.co, s.cfg, s.lastErr = co, cfg, ""
	s.mu.Unlock()
}

func (s *server) setErr(msg string) {
	s.mu.Lock()
	s.lastErr = msg
	s.mu.Unlock()
}

func (s *server) current() (*coordinator, config) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.co, s.cfg
}

// requestReload asks the supervisor loop to rebuild from disk. Non-blocking:
// if a rebuild is already pending, this one is already covered by it.
func (s *server) requestReload() {
	select {
	case s.reloadC <- struct{}{}:
	default:
	}
}

// listen binds the status address, rebinding if it has changed.
//
// Rebinding is the one part of a reload the operator can actually feel: the
// page they are looking at is served from here. It is still worth supporting,
// because the alternative is a field that silently does nothing until the next
// restart, and the dashboard already shows a red dot and retries every couple
// of seconds when it cannot reach the server.
func (s *server) listen(addr string) error {
	if s.srv != nil && s.addr == addr {
		return nil
	}
	if s.srv != nil {
		log.Printf("status listener moving from %s to %s", s.addr, addr)
		_ = s.srv.Close()
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("status listener on %s: %w", addr, err)
	}
	// IdleTimeout is set explicitly because the default is none, and a
	// keep-alive connection that either side may close at any moment races
	// with the dashboard's two-second poll: the browser writes a request onto
	// a socket the server is closing, and reports ERR_EMPTY_RESPONSE. Harmless
	// -- the next poll succeeds -- but it fills the console with errors that
	// look like a server fault, on a page whose whole job is to be believed.
	//
	// Comfortably longer than any sane poll interval, so the connection is
	// reused rather than reopened, and finite so a walked-away-from tab does
	// not hold a socket forever.
	s.srv = &http.Server{
		Handler:     s.routes(),
		IdleTimeout: 120 * time.Second,
		ReadTimeout: 15 * time.Second,
	}
	s.addr = addr
	go func(srv *http.Server, ln net.Listener) {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("status server stopped: %v", err)
		}
	}(s.srv, ln)
	log.Printf("status on %s (JSON at /status)", browseURL(addr))
	return nil
}

func (s *server) close() {
	if s.srv != nil {
		_ = s.srv.Close()
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// mustPost rejects anything that is not a POST.
//
// Every endpoint that changes something is POST-only, so nothing here is
// reachable by a link, a prefetch, or an address bar. Resetting the statistics
// or rewriting the config by accident should take deliberate effort.
func mustPost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodPost {
		return true
	}
	w.Header().Set("Allow", "POST")
	http.Error(w, "POST required", http.StatusMethodNotAllowed)
	return false
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		co, _ := s.current()
		if co == nil {
			writeJSON(w, http.StatusOK, statusDoc{Version: versionString()})
			return
		}
		doc := co.status()
		s.mu.RLock()
		doc.ReloadError = s.lastErr
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, doc)
	})

	// Rotate now, on request.
	//
	// Deliberately NOT subject to the dwell floor. That floor exists to stop a
	// burst of fast blocks spending more time reconnecting than hashing -- it
	// is a guard against the chain, not against the operator. Someone who has
	// looked at a quiet chain and decided to move their rigs has already made
	// the judgement the floor exists to make on their behalf.
	mux.HandleFunc("/rotate", func(w http.ResponseWriter, r *http.Request) {
		if !mustPost(w, r) {
			return
		}
		co, _ := s.current()
		if co == nil || len(co.cfg.Pools) == 0 {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "nothing to rotate"})
			return
		}
		co.rotate("manual rotation requested from the dashboard")
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})

	mux.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		if !mustPost(w, r) {
			return
		}
		if co, _ := s.current(); co != nil {
			co.resetStats()
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})

	// The config as it is on disk right now. This is what the editor loads,
	// and it is deliberately the file's own shape rather than a UI-specific
	// projection -- someone editing config.json by hand and someone editing it
	// through this form should be looking at the same thing.
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cfg, err := loadConfig(s.path)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"config":     cfg,
				"configured": cfg.configured(),
				"path":       s.path,
			})
		case http.MethodPost:
			s.saveAndReload(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
		}
	})

	// Port helpers for the editor. Both are read-only questions about this
	// machine, which is why they are safe to answer and why they are answered
	// HERE rather than guessed at in the browser -- a page has no way to find
	// out whether a port on the host is free.
	mux.HandleFunc("/ports/probe", func(w http.ResponseWriter, r *http.Request) {
		if !mustPost(w, r) {
			return
		}
		var body struct {
			Listen string `json:"listen"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request body"})
			return
		}
		addr := normaliseListen(body.Listen)
		// A port this switchyard is already listening on is not "taken" in
		// any sense the operator cares about -- it is theirs. Saying
		// "address in use" about your own rig's port would be nonsense.
		if _, cfg := s.current(); addrInUseByUs(cfg, addr) {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mine": true})
			return
		}
		if err := probeListen(addr); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// Ask a DATUM gateway about itself.
	//
	// This is the answer to "why should the operator have to type in what the
	// gateway already knows". DATUM serves a status page that names the pool
	// it is connected to, and the fields switchyard cannot otherwise discover
	// are sitting right there in it.
	//
	// Fetched by the SERVER, not the browser: the gateway is frequently on a
	// network only this process can reach, and a page cannot read a response
	// from another origin anyway.
	mux.HandleFunc("/gateway/inspect", func(w http.ResponseWriter, r *http.Request) {
		if !mustPost(w, r) {
			return
		}
		var body struct {
			Host       string `json:"host"`
			StatusPort int    `json:"statusPort"`
			Port       int    `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request body"})
			return
		}
		// TWO INDEPENDENT CHECKS, ALWAYS BOTH REPORTED.
		//
		// These are separate services on separate ports and either can be
		// wrong on its own, so neither is allowed to short-circuit the other.
		// The earlier version returned as soon as the status page failed,
		// which meant a correct stratum port went unmentioned whenever the
		// status port was wrong -- the operator saw one red line and no way to
		// tell that half their entry was already right.
		probe := poolConfig{Host: body.Host, Port: body.Port, StatusPort: body.StatusPort}
		out := map[string]any{}

		if body.StatusPort <= 0 {
			out["statusOK"] = false
			out["statusError"] = "not set"
		} else if info, err := inspectGateway(r.Context(), probe.apiURL()); err != nil {
			out["statusOK"] = false
			out["statusError"] = shortReachError(err, body.StatusPort)
		} else {
			out["statusOK"] = true
			out["info"] = info
		}

		switch {
		case body.Port <= 0:
			out["stratumOK"] = false
			out["stratumError"] = "not set"
		case body.Port == body.StatusPort:
			// Named outright, because the probe cannot say so on its own.
			// DATUM's status server answers a stratum subscribe by hanging up
			// rather than replying, so the honest probe result is "closed the
			// connection" -- true, and no help at all to somebody who has just
			// put the same number in both boxes.
			out["stratumOK"] = false
			out["stratumError"] = "same as the status port"
		default:
			if err := probeStratum(r.Context(), probe.stratumAddr()); err != nil {
				out["stratumOK"] = false
				out["stratumError"] = err.Error()
			} else {
				out["stratumOK"] = true
			}
		}

		// "ok" still means the status page answered, because that is what
		// names the pool and older callers read it that way.
		out["ok"] = out["statusOK"]
		writeJSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("/ports/suggest", func(w http.ResponseWriter, r *http.Request) {
		_, cfg := s.current()
		taken := map[int]bool{}
		for _, rig := range cfg.Rigs {
			if _, p, err := net.SplitHostPort(rig.Listen); err == nil {
				if n, err := strconv.Atoi(p); err == nil {
					taken[n] = true
				}
			}
		}
		// Extra ports the caller already has pencilled into an unsaved form.
		for _, raw := range strings.Split(r.URL.Query().Get("taken"), ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
				taken[n] = true
			}
		}
		port := suggestPort(defaultRigPortBase, taken)
		if port == 0 {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "port": port, "listen": fmt.Sprintf("0.0.0.0:%d", port),
		})
	})

	return mux
}

// defaultRigPortBase is where port suggestions start.
//
// Nothing depends on this number; it is simply high enough to be out of the
// way of anything registered and low enough to be memorable. Miners are
// pointed at whatever ends up in the config, not at this.
const defaultRigPortBase = 23401

func addrInUseByUs(cfg config, addr string) bool {
	for _, r := range cfg.Rigs {
		if normaliseListen(r.Listen) == addr {
			return true
		}
	}
	return false
}

// browseURL turns a bind address into something an operator can paste into a
// browser. A wildcard bind is written ":7160" or "0.0.0.0:7160", neither of
// which is a URL a browser will accept -- and telling somebody to open a URL
// that does not work is worse than telling them nothing.
func browseURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr + "/"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port) + "/"
}

// normaliseListen turns the forms an operator will actually type into a listen
// address. A bare port is by far the most common thing to type, and refusing
// it would be pedantry.
func normaliseListen(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.Contains(v, ":") {
		return "0.0.0.0:" + v
	}
	if strings.HasPrefix(v, ":") {
		return "0.0.0.0" + v
	}
	return v
}

// saveAndReload is the only path that changes the running system.
//
// The order matters and is the point of the whole feature:
//
//	validate -> WRITE THE FILE -> re-read the file -> rebuild from it
//
// The running system is never built from the struct that arrived in the
// request. It is built from the file, by the same loadConfig every cold boot
// uses. That makes divergence between "changed in the UI" and "booted from
// disk" impossible rather than merely unlikely -- if a round trip through JSON
// drops a field, applies a default, or normalises a value, the operator sees
// that immediately instead of discovering it weeks later when the process
// restarts.
//
// It also means this endpoint is a convenience, never a requirement. Editing
// config.json by hand and restarting reaches exactly the same place.
func (s *server) saveAndReload(w http.ResponseWriter, r *http.Request) {
	// Same decoder as the file path, so the two cannot disagree about what a
	// valid config is. See decodeConfig.
	incoming, err := decodeConfig(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "could not parse config: " + err.Error()})
		return
	}

	for i := range incoming.Rigs {
		incoming.Rigs[i].Listen = normaliseListen(incoming.Rigs[i].Listen)
	}
	incoming.StatusListen = normaliseListen(incoming.StatusListen)
	// Raw values first. applyDefaults treats anything <= 0 as "not set" and
	// substitutes a default, which is right for an omitted field in a file and
	// wrong for a number somebody typed -- a dwell floor of -5 would quietly
	// become 60 and the operator would never learn their input was discarded.
	if err := incoming.validateRaw(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	incoming.applyDefaults()

	if err := incoming.validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Bind-check every rig port before committing anything. A config that
	// parses perfectly and cannot listen is still a config that leaves miners
	// with nowhere to connect, and it is far better to refuse the form than to
	// write a file that breaks the next boot too.
	_, running := s.current()
	for _, rig := range incoming.Rigs {
		if addrInUseByUs(running, rig.Listen) {
			continue
		}
		if err := probeListen(rig.Listen); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("rig cannot listen on %s: %v", rig.Listen, err),
			})
			return
		}
	}

	// AND THE DASHBOARD'S OWN ADDRESS, which is the one that can leave nothing
	// to fix things from.
	//
	// The rig loop above refuses the form rather than writing a file that
	// breaks the next boot. statusListen needs that more than any rig port
	// does, not less: listen() closes the current listener before binding the
	// new one, and main() treats a failed bind as fatal. So an unbindable
	// value here writes a valid file, takes the whole process down with every
	// rig on it, and then fails identically on every restart -- because the
	// file is now on disk. main()'s own comment claims this is unreachable
	// ("a reload can only follow a config that was validated before being
	// written"); this is the check that makes that true.
	//
	// It is also the edit the README tells people to make, when it suggests
	// moving the dashboard to 127.0.0.1 on an untrusted network.
	//
	// Unchanged means already ours: listen() returns early without rebinding,
	// so probing it would only discover that we are holding it.
	if incoming.StatusListen != "" &&
		incoming.StatusListen != normaliseListen(running.StatusListen) {
		if err := probeListen(incoming.StatusListen); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("the dashboard cannot listen on %s: %v", incoming.StatusListen, err),
			})
			return
		}
	}

	if err := saveConfig(s.path, incoming); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "could not write " + s.path + ": " + err.Error(),
		})
		return
	}
	log.Printf("config written to %s by the dashboard; rebuilding from disk", s.path)

	// Answer BEFORE the rebuild. The rebuild drops every rig session and may
	// move this very listener, so a response written afterwards might never
	// arrive. The page polls its way back to a live dashboard on its own.
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "reloading": true})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	s.requestReload()
}

// settleDelay is how long the supervisor waits after cancelling a generation
// before binding the next one.
//
// Listeners close on context cancellation, but the goroutines doing it are
// scheduled, not instantaneous, and a rebind racing a not-quite-closed socket
// fails with "address already in use" -- which would turn every config save
// into a coin flip. A short pause costs nothing on a change that happens by
// hand, occasionally.
const settleDelay = 250 * time.Millisecond

// gatewayInfo is what a DATUM gateway will tell anyone who asks.
type gatewayInfo struct {
	PoolHost string `json:"poolHost"`
	Status   string `json:"status"`
	Tag      string `json:"tag"`
}

// shortReachError turns a Go transport error into one line an operator can act
// on.
//
// The raw text is accurate and unusable: a wrong port produced roughly a
// hundred characters of nested wrapping -- the URL, the method, the resolved
// IP, the syscall -- which overflowed the card and told the reader nothing
// they did not already know. They typed a port; the answer is about that port.
func shortReachError(err error, port int) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Sprintf("port %d did not answer in time", port)
	}
	// The sentinel first, because the text differs by platform: Linux says
	// "connection refused" and Windows says "connectex: No connection could be
	// made because the target machine actively refused it". Matching on words
	// alone silently degraded to the raw error on one of the two.
	if errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Sprintf("nothing is listening on port %d", port)
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "actively refused"):
		return fmt.Sprintf("nothing is listening on port %d", port)
	case strings.Contains(msg, "no such host"):
		return "no host by that name"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline exceeded"):
		return fmt.Sprintf("port %d did not answer in time", port)
	case strings.Contains(msg, "no DATUM"), strings.Contains(msg, "not a DATUM"):
		return msg
	}
	// Anything unclassified keeps its own words, trimmed of the transport
	// wrapping that carries no information for a reader.
	if i := strings.Index(msg, ": Get \""); i > 0 {
		return msg[:i]
	}
	return msg
}

// inspectGateway reads a DATUM gateway's status page.
//
// It scrapes HTML, which is not something to be proud of, but the alternative
// is asking every operator to look up their own pool's hostname and type it in
// -- and a field that has to be looked up by hand is a field that stays empty.
// The page is a local service, the parse is best-effort, and nothing depends
// on it: a failure fills in nothing and the operator types it themselves.
//
// WHAT IT CANNOT TELL US, and this is the important part: the gateway's
// pool_pass_full_users setting lives behind admin authentication, on /config.
// So switchyard cannot determine whether a payout address needs prepending to
// the worker name, and does not guess -- there is no config field for one and
// no code path that would edit a username. The operator's side of that is
// documented under "One requirement on your gateways" in the README.
func inspectGateway(ctx context.Context, rawURL string) (*gatewayInfo, error) {
	info, _, err := fetchGatewayStatus(ctx, rawURL)
	return info, err
}

// fetchGatewayStatus does the fetch and the parse, returning the flattened page
// text as well so callers that want more out of it -- the health poller wants
// the share counters -- do not have to fetch it twice or reimplement the parse.
func fetchGatewayStatus(ctx context.Context, rawURL string) (*gatewayInfo, string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, "", fmt.Errorf("no gateway API address given")
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", fmt.Errorf("not a usable address: %w", err)
	}
	// Only ever plain HTTP(S) to a host and port. This takes an address from
	// the browser and fetches it server-side, so it is worth being explicit
	// that it will not be talked into reading a file.
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, "", fmt.Errorf("only http and https are supported, not %q", u.Scheme)
	}
	u.Path, u.RawQuery, u.Fragment = "/", "", ""

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("could not reach %s: %w", u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%s answered %s", u.Host, resp.Status)
	}
	// Bounded read: a status page that streams forever should not be able to
	// exhaust memory here.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, "", err
	}

	text := stripTags(string(body))
	info := &gatewayInfo{
		PoolHost: firstGroup(poolHostRE, text),
		Status:   firstGroup(statusRE, text),
		Tag:      firstGroup(poolTagRE, text),
	}
	if info.PoolHost == "" {
		return nil, "", fmt.Errorf("%s responded, but does not look like a DATUM gateway status page", u.Host)
	}
	// The status page prints host and port together; the port is the pool's
	// stratum port, of no interest here and only clutter in a label.
	if i := strings.LastIndex(info.PoolHost, ":"); i > 0 {
		info.PoolHost = info.PoolHost[:i]
	}
	return info, text, nil
}

// Targeted patterns rather than a general "value after a label" scan.
//
// The general version looked tidier and was quietly wrong: it ran past the end
// of each value into the beginning of the next label, so "Connected and Ready"
// came back as "Connected and Ready Pool". Half-parsed values are worse than
// absent ones -- they get written into a config and displayed as fact -- so
// each field states exactly where it ends.
var (
	poolHostRE = regexp.MustCompile(`Pool Host:\s*(\S+)`)
	statusRE   = regexp.MustCompile(`Status:\s*([A-Za-z][A-Za-z ]*?)\s+Pool Host:`)
	poolTagRE  = regexp.MustCompile(`Pool Tag:\s*"([^"]*)"`)
)

func firstGroup(re *regexp.Regexp, text string) string {
	if m := re.FindStringSubmatch(text); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

var htmlTagRE = regexp.MustCompile(`(?s)<[^>]*>`)
var spaceRE = regexp.MustCompile(`\s+`)

func stripTags(h string) string {
	return strings.TrimSpace(spaceRE.ReplaceAllString(htmlTagRE.ReplaceAllString(h, " "), " "))
}
