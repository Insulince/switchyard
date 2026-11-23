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

	"github.com/Insulince/switchyard/sv2/noise"
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

	// The DATUM gate's two states for the current generation (datumgate.go):
	// still waiting for a gateway to identify itself, or refused outright.
	// Either way nothing is mining, and the page has to say why.
	gateWaiting string
	gateRefused string

	srv  *http.Server
	addr string

	// feed is the share event stream behind /shares/stream. Here rather than
	// on the coordinator for the same reason the server is: it outlives a
	// reload, and so does a dashboard's subscription to it.
	feed *shareFeed

	// staged holds SV2 authority secrets the editor has generated but not yet
	// saved, keyed by an opaque handle. The browser is handed the handle and the
	// matching PUBLIC key; the private secret stays HERE until a save resolves it
	// into config.json, so a generated secret never reaches the browser. Unsaved
	// ones are discarded on restart -- no harm, nothing references them. On s
	// (not the coordinator) because, like feed, it must outlive a reload.
	stagedMu    sync.Mutex
	staged      map[string]string
	stagedOrder []string // handles oldest first, for the cap in stageSecret
}

// maxStaged bounds the unsaved secrets held at once. An editor session stages
// one per Generate click; far more than this unsaved at a time is something
// other than a person editing, and must not grow memory without limit.
const maxStaged = 32

func newServer(path string) *server {
	return &server{path: path, reloadC: make(chan struct{}, 1), feed: newShareFeed(), staged: map[string]string{}}
}

// stageSecret stores a freshly minted authority secret under a new handle and
// returns the handle. The secret waits here, off the browser, until a save
// resolves it.
func (s *server) stageSecret(secret string) string {
	h := randomHex(16)
	s.stagedMu.Lock()
	s.staged[h] = secret
	s.stagedOrder = append(s.stagedOrder, h)
	// Over the cap, drop the oldest still-unsaved handles. Order entries whose
	// handle was already consumed are skipped as they surface.
	for len(s.staged) > maxStaged && len(s.stagedOrder) > 0 {
		old := s.stagedOrder[0]
		s.stagedOrder = s.stagedOrder[1:]
		delete(s.staged, old)
	}
	// Consumed handles leave stale order entries; compact once they dominate.
	if len(s.stagedOrder) > 2*maxStaged {
		live := s.stagedOrder[:0]
		for _, k := range s.stagedOrder {
			if _, ok := s.staged[k]; ok {
				live = append(live, k)
			}
		}
		s.stagedOrder = live
	}
	s.stagedMu.Unlock()
	return h
}

// consumeStaged returns the secret for a handle and removes it, so a staged
// secret is spent once -- by the save that resolves it -- and does not pile up.
func (s *server) consumeStaged(handle string) (string, bool) {
	s.stagedMu.Lock()
	defer s.stagedMu.Unlock()
	sec, ok := s.staged[handle]
	if ok {
		delete(s.staged, handle)
	}
	return sec, ok
}

// swap installs a newly built coordinator. Called once at boot and once per
// successful reload.
func (s *server) swap(co *coordinator, cfg config) {
	s.mu.Lock()
	s.co, s.cfg, s.lastErr = co, cfg, ""
	s.gateWaiting, s.gateRefused = "", ""
	s.mu.Unlock()
}

func (s *server) setGate(waiting, refused string) {
	s.mu.Lock()
	s.gateWaiting, s.gateRefused = waiting, refused
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

// shareBeat is how often an idle share stream sends a comment line. It keeps
// an intermediary from timing the connection out, and it is how a stream to a
// browser that vanished without closing gets noticed: the write fails.
const shareBeat = 15 * time.Second

// serveShareStream pushes share events to one dashboard as server-sent
// events, for as long as it stays connected. See shareFeed.
func (s *server) serveShareStream(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	// A reverse proxy in front of the dashboard would otherwise buffer the
	// stream and deliver it in lumps, which is the one thing it exists not to do.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	events, unsubscribe := s.feed.subscribe()
	defer unsubscribe()

	if _, err := io.WriteString(w, ": open\n\n"); err != nil || rc.Flush() != nil {
		return
	}
	beat := time.NewTicker(shareBeat)
	defer beat.Stop()
	for {
		var err error
		select {
		case <-r.Context().Done():
			return
		case <-beat.C:
			_, err = io.WriteString(w, ": beat\n\n")
		case ev := <-events:
			b, _ := json.Marshal(ev)
			_, err = fmt.Fprintf(w, "data: %s\n\n", b)
		}
		if err != nil || rc.Flush() != nil {
			return
		}
	}
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

// requireJSONBody is a CSRF guard: it rejects a request whose Content-Type is not
// application/json. A cross-site <form> can only send text/plain, urlencoded or
// multipart, and a cross-site fetch that sets application/json triggers a CORS
// preflight this origin never answers -- so only the dashboard's own page reaches
// a guarded endpoint. It matters most where the handler dials a caller-supplied
// host (the gateway probes), which would otherwise be an SSRF reachable by CSRF.
func requireJSONBody(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if strings.TrimSpace(ct) != "application/json" {
		http.Error(w, "Content-Type: application/json required", http.StatusUnsupportedMediaType)
		return false
	}
	return true
}

// mustPostJSON requires a POST carrying a JSON body: the method check plus the
// CSRF guard above. Used by every endpoint that decodes a JSON body.
func mustPostJSON(w http.ResponseWriter, r *http.Request) bool {
	return mustPost(w, r) && requireJSONBody(w, r)
}

// hostAllowed is the DNS-rebinding guard: it accepts a Host header only when
// it names an IP literal or localhost.
//
// requireJSONBody stops OTHER origins, and DNS rebinding is how a hostile
// page stops being another origin: it serves itself from a name it controls,
// then re-points that name at this machine's address. The browser still calls
// the origin attacker.example, so its fetches are same-origin, the JSON
// guard's preflight never happens, and every endpoint -- POST /config
// included -- is in reach. What the rebound request cannot change is its Host
// header: it still says attacker.example. Nobody legitimately reaches this
// dashboard by an arbitrary DNS name -- it is opened as localhost:<port>, or
// by a LAN IP from another machine -- so refusing every name except localhost
// closes the attack without a token, a login or a setting.
func hostAllowed(host string) bool {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	}
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	if h == "" {
		return false
	}
	lh := strings.ToLower(h)
	if lh == "localhost" || strings.HasSuffix(lh, ".localhost") {
		return true
	}
	return net.ParseIP(h) != nil
}

func guardHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host) {
			http.Error(w, "switchyard answers only to localhost or an IP address, not "+
				strconv.Quote(r.Host), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) routes() http.Handler {
	return guardHost(s.mux())
}

func (s *server) mux() http.Handler {
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
		doc.GateWaiting, doc.GateRefused = s.gateWaiting, s.gateRefused
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, doc)
	})

	mux.HandleFunc("/shares/stream", s.serveShareStream)

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
			// A browser has no business holding switchyard's own SV2 secrets, so
			// this is the one place the GET is a projection rather than the file
			// verbatim: each sv2 rig's authoritySecret is replaced by the __keep__
			// sentinel (the editor sends it back unchanged to preserve the secret,
			// never seeing it), and the PUBLIC half -- the part an operator pins on
			// a miner -- is handed over separately. A pool's authorityKey is
			// already public, so it is returned as-is.
			redacted := cfg
			redacted.Rigs = append([]rigConfig(nil), cfg.Rigs...)
			rigPub := map[string]string{}
			for i := range redacted.Rigs {
				if redacted.Rigs[i].proto() != "sv2" || redacted.Rigs[i].AuthoritySecret == "" {
					continue
				}
				if priv, err := redacted.Rigs[i].authorityPriv(); err == nil {
					rigPub[strconv.Itoa(redacted.Rigs[i].Port)] = authorityKeyEncode(priv.PubKey())
				}
				redacted.Rigs[i].AuthoritySecret = authSecretKeep
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"config":          redacted,
				"configured":      cfg.configured(),
				"path":            s.path,
				"rigAuthorityPub": rigPub,
			})
		case http.MethodPost:
			if !requireJSONBody(w, r) {
				return
			}
			s.saveAndReload(w, r)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
		}
	})

	// Derive the PUBLIC half of an SV2 authority secret the operator typed into
	// the editor, so the page can show the key to pin on a miner without doing
	// crypto in the browser. The secret is one the operator is supplying anyway
	// -- it is on its way into config.json -- so echoing its public half back
	// leaks nothing the save itself would not.
	mux.HandleFunc("/authority/pubof", func(w http.ResponseWriter, r *http.Request) {
		if !mustPostJSON(w, r) {
			return
		}
		var body struct {
			Secret string `json:"secret"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request body"})
			return
		}
		priv, err := authoritySecretDecode(body.Secret)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"publicKey": authorityKeyEncode(priv.PubKey())})
	})

	// Mint a fresh SV2 authority identity for the editor and STAGE it: the secret
	// stays server-side under a handle, and only the handle and the PUBLIC key go
	// back, so a generated private key never reaches the browser. The handle
	// rides in the rig's authoritySecret as "__staged__:<handle>" until a save
	// resolves it (saveAndReload) or the process restarts and discards it.
	mux.HandleFunc("/authority/generate", func(w http.ResponseWriter, r *http.Request) {
		// JSON-guarded like its siblings even though it reads no body: a bare
		// mustPost let any page's cross-site form mint and stage secrets.
		if !mustPostJSON(w, r) {
			return
		}
		secret, err := newAuthoritySecret()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		priv, err := authoritySecretDecode(secret)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"handle":    s.stageSecret(secret),
			"publicKey": authorityKeyEncode(priv.PubKey()),
		})
	})

	// Validate a gateway authority PUBLIC key the operator pasted, decoding it
	// exactly as switchyard will when it dials the gateway, so the editor can
	// warn about a malformed key before a save would reject it. Public in,
	// public out.
	mux.HandleFunc("/authority/checkkey", func(w http.ResponseWriter, r *http.Request) {
		if !mustPostJSON(w, r) {
			return
		}
		var body struct {
			Key string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request body"})
			return
		}
		if _, err := authorityKeyDecode(body.Key); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// Prove a pasted gateway authority key is the RIGHT one, not merely
	// well-formed (that is /authority/checkkey). There is no "ask the gateway
	// for its key" request in SV2 -- the key is never sent in the clear. The
	// only thing that confirms it is completing the handshake switchyard would
	// run in production: dial the gateway's stratum port as the Noise initiator
	// with this key pinned, and see whether the gateway's certificate verifies
	// under it. It does only if the gateway's real authority key is this one.
	//
	// This is exactly sv2Upstream.run's first step and nothing more: the socket
	// is dropped the instant the handshake resolves, so no channel is opened and
	// no mining session is touched. Done by the SERVER because the gateway is
	// often on a network only this process can reach.
	mux.HandleFunc("/authority/probe", func(w http.ResponseWriter, r *http.Request) {
		if !mustPostJSON(w, r) {
			return
		}
		var body struct {
			Host string `json:"host"`
			Port int    `json:"port"`
			Key  string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request body"})
			return
		}
		pub, err := authorityKeyDecode(body.Key)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if body.Port <= 0 || body.Port > 65535 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "set the stratum port first"})
			return
		}
		// Build the address with the same helper production dials through, so the
		// probe reaches exactly where a live SV2 session would.
		addr := poolConfig{Host: body.Host, Port: body.Port}.stratumAddr()
		conn, _, err := sv2DialInitiator(addr, pub, 8*time.Second)
		if err == nil {
			// Verified: the gateway's certificate validated under this key. Drop
			// the socket at once -- we were only ever asking a yes/no question.
			_ = conn.Close()
			writeJSON(w, http.StatusOK, map[string]any{"verified": true, "reached": true})
			return
		}
		switch {
		case errors.Is(err, noise.ErrCertSignatureInvalid):
			// A real SV2 gateway answered and its certificate decrypted -- the
			// signature just did not validate under this key. The key is wrong.
			writeJSON(w, http.StatusOK, map[string]any{
				"verified": false, "reached": true,
				"error": "the gateway is using a different authority key than this one",
			})
		case errors.Is(err, noise.ErrCertWindow):
			// Reached the gateway, but its certificate's validity window is
			// checked before the signature, so the key could not be confirmed.
			// This is almost always a clock, not a wrong key.
			writeJSON(w, http.StatusOK, map[string]any{
				"verified": false, "reached": true, "window": true,
				"error": "the gateway's certificate is outside its validity window (check the clocks); the key could not be confirmed",
			})
		default:
			// Never got a certificate to check: a dial failure, or something on
			// that port that is not an SV2 gateway. The key was not tested.
			writeJSON(w, http.StatusOK, map[string]any{
				"verified": false, "reached": false,
				"error": shortReachError(err, body.Port),
			})
		}
	})

	// Port helpers for the editor. Both are read-only questions about this
	// machine, which is why they are safe to answer and why they are answered
	// HERE rather than guessed at in the browser -- a page has no way to find
	// out whether a port on the host is free.
	mux.HandleFunc("/ports/probe", func(w http.ResponseWriter, r *http.Request) {
		if !mustPostJSON(w, r) {
			return
		}
		var body struct {
			Port int `json:"port"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request body"})
			return
		}
		if body.Port <= 0 || body.Port > 65535 {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "not a valid port"})
			return
		}
		addr := fmt.Sprintf("0.0.0.0:%d", body.Port)
		// A port this switchyard is already listening on is not "taken" in
		// any sense the operator cares about -- it is theirs. Saying
		// "address in use" about your own rig's port would be nonsense.
		if _, cfg := s.current(); addrInUseByUs(cfg, body.Port) {
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
		if !mustPostJSON(w, r) {
			return
		}
		var body struct {
			Host       string `json:"host"`
			StatusPort int    `json:"statusPort"`
			Port       int    `json:"port"`
			Protocol   string `json:"protocol"`
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
			// Protocol-aware: the two wires are incompatible, so an SV2 gateway
			// must be probed with the SV2 handshake, not an SV1 subscribe. Using
			// the wrong one is exactly what reported a live SV2 gateway as "not a
			// stratum server".
			probeFn := probeStratum
			if body.Protocol == "sv2" {
				probeFn = probeStratumSV2
			}
			if err := probeFn(r.Context(), probe.stratumAddr()); err != nil {
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
			taken[rig.Port] = true
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
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "port": port})
	})

	return mux
}

// defaultRigPortBase is where port suggestions start.
//
// Nothing depends on this number; it is simply high enough to be out of the
// way of anything registered and low enough to be memorable. Miners are
// pointed at whatever ends up in the config, not at this.
const defaultRigPortBase = 23401

func addrInUseByUs(cfg config, port int) bool {
	for _, r := range cfg.Rigs {
		if r.Port == port {
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

	// Rig ports and the dashboard port are plain integers now -- nothing to
	// normalise, and validate rejects a port out of range.
	// Raw values first. applyDefaults treats anything <= 0 as "not set" and
	// substitutes a default, which is right for an omitted field in a file and
	// wrong for a number somebody typed -- a dwell floor of -5 would quietly
	// become 60 and the operator would never learn their input was discarded.
	if err := incoming.validateRaw(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	incoming.applyDefaults()

	// Turn the editor's SV2 identity references into real secrets BEFORE
	// validation. Staged (in-screen generated) handles first: swap each
	// "__staged__:<handle>" for the secret parked server-side, consuming it. A
	// missing handle means the process restarted since it was generated -- the
	// secret is gone, so the operator must regenerate rather than save a key
	// whose public half they may already have pinned on a miner.
	for i := range incoming.Rigs {
		sec := incoming.Rigs[i].AuthoritySecret
		if !strings.HasPrefix(sec, stagedPrefix) {
			continue
		}
		real, ok := s.consumeStaged(strings.TrimPrefix(sec, stagedPrefix))
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("rig on port %d: its generated SV2 identity expired (switchyard restarted); "+
					"open the editor and regenerate it", incoming.Rigs[i].Port),
			})
			return
		}
		incoming.Rigs[i].AuthoritySecret = real
	}
	// Then the __keep__ / __generate__ sentinels, using the running config as the
	// source of any "keep" secret. After this, validate sees real secrets only.
	_, running := s.current()
	if err := resolveRigIdentities(&incoming, running); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if err := incoming.validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Bind-check every rig port before committing anything. A config that
	// parses perfectly and cannot listen is still a config that leaves miners
	// with nowhere to connect, and it is far better to refuse the form than to
	// write a file that breaks the next boot too. (running was read above.)
	for _, rig := range incoming.Rigs {
		if addrInUseByUs(running, rig.Port) {
			continue
		}
		if err := probeListen(rig.listenAddr()); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("rig cannot listen on port %d: %v", rig.Port, err),
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
	if incoming.DashboardPort != running.DashboardPort {
		if err := probeListen(incoming.dashboardAddr()); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("the dashboard cannot listen on port %d: %v", incoming.DashboardPort, err),
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
	text, host, err := fetchGatewayPage(ctx, rawURL)
	if err != nil {
		return nil, "", err
	}
	if !isDatumPage(text) {
		return nil, "", fmt.Errorf("%s responded, but %w", host, errNotDatum)
	}
	info := &gatewayInfo{
		PoolHost: firstGroup(poolHostRE, text),
		Status:   firstGroup(statusRE, text),
		Tag:      firstGroup(poolTagRE, text),
	}
	if info.PoolHost == "" {
		return nil, "", fmt.Errorf("%s is a DATUM gateway, but its status page names no pool host", host)
	}
	// The status page prints host and port together; the port is the pool's
	// stratum port, of no interest here and only clutter in a label.
	if i := strings.LastIndex(info.PoolHost, ":"); i > 0 {
		info.PoolHost = info.PoolHost[:i]
	}
	return info, text, nil
}

// fetchGatewayPage fetches a status page and flattens it to text, and says
// nothing about what the page is. An error here means nothing usable answered
// -- the transport failed or the server refused -- which is a different fact
// from "something answered and it is not DATUM", and the DATUM gate treats the
// two very differently. See datumgate.go.
func fetchGatewayPage(ctx context.Context, rawURL string) (text, host string, err error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", "", fmt.Errorf("no gateway API address given")
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", fmt.Errorf("not a usable address: %w", err)
	}
	// Only ever plain HTTP(S) to a host and port. This takes an address from
	// the browser and fetches it server-side, so it is worth being explicit
	// that it will not be talked into reading a file.
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", fmt.Errorf("only http and https are supported, not %q", u.Scheme)
	}
	u.Path, u.RawQuery, u.Fragment = "/", "", ""

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("could not reach %s: %w", u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("%s answered %s", u.Host, resp.Status)
	}
	// Bounded read: a status page that streams forever should not be able to
	// exhaust memory here.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", err
	}

	return stripTags(string(body)), u.Host, nil
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
	// The hyphen matters: "Non-Pooled Mode" is the status that means the
	// gateway has lost its pool, and a class without it parsed that as an
	// empty string -- so the one status worth catching was the one that
	// vanished.
	statusRE  = regexp.MustCompile(`Status:\s*([A-Za-z][A-Za-z -]*?)\s+Pool Host:`)
	poolTagRE = regexp.MustCompile(`Pool Tag:\s*"([^"]*)"`)
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
