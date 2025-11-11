package server

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"git.mills.io/prologic/smtpd"
	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// smtpConversation holds the protocol conversation lines for a single SMTP connection
type smtpConversation struct {
	lines []string
	mu    sync.Mutex
}

// SMTPServer is a smtp server instance that listens both
// TLS and Non-TLS based servers.
type SMTPServer struct {
	options     *Options
	smtpServer  smtpd.Server
	smtpsServer smtpd.Server
	// NOTE: This is susceptable to race condition on multiple requests coming from the same
	// remote address. I.e., the SMTP streams may get mixed. I found no way besides changing
	// smtpd to fix this.
	conversationMap sync.Map // keyed by remote address
}

// createLogHandler returns a LogFunc that captures SMTP protocol lines (both client and server)
func (h *SMTPServer) createLogHandler() smtpd.LogFunc {
	return func(remoteIP, verb, line string) {
		conv, _ := h.conversationMap.LoadOrStore(remoteIP, &smtpConversation{})
		c := conv.(*smtpConversation)
		c.mu.Lock()
		c.lines = append(c.lines, line)
		c.mu.Unlock()
	}
}

// NewSMTPServer returns a new TLS & Non-TLS SMTP server.
func NewSMTPServer(options *Options) (*SMTPServer, error) {
	server := &SMTPServer{options: options}

	// Enable debug mode in smtpd library to activate LogRead/LogWrite callbacks
	smtpd.Debug = true

	authHandler := func(remoteAddr net.Addr, mechanism string, username []byte, password []byte, shared []byte) (bool, error) {
		return true, nil
	}
	rcptHandler := func(remoteAddr net.Addr, from string, to string) bool {
		return true
	}

	logHandler := server.createLogHandler()

	server.smtpServer = smtpd.Server{
		Addr:        fmt.Sprintf("%s:%d", options.ListenIP, options.SmtpPort),
		AuthHandler: authHandler,
		HandlerRcpt: rcptHandler,
		Hostname:    options.Domains[0],
		Appname:     "interactsh",
		Handler:     smtpd.Handler(server.defaultHandler),
		LogRead:     logHandler,
		LogWrite:    logHandler,
	}
	server.smtpsServer = smtpd.Server{
		Addr:        fmt.Sprintf("%s:%d", options.ListenIP, options.SmtpsPort),
		AuthHandler: authHandler,
		HandlerRcpt: rcptHandler,
		Hostname:    options.Domains[0],
		Appname:     "interactsh",
		Handler:     smtpd.Handler(server.defaultHandler),
		LogRead:     logHandler,
		LogWrite:    logHandler,
	}
	return server, nil
}

// ListenAndServe listens on smtp and/or smtps ports for the server.
func (h *SMTPServer) ListenAndServe(tlsConfig *tls.Config, smtpAlive, smtpsAlive chan bool) {
	go func() {
		if tlsConfig == nil {
			return
		}

		logHandler := h.createLogHandler()

		srv := &smtpd.Server{
			Addr:      fmt.Sprintf("%s:%d", h.options.ListenIP, h.options.SmtpAutoTLSPort),
			Handler:   h.defaultHandler,
			Appname:   "interactsh",
			Hostname:  h.options.Domains[0],
			LogRead:   logHandler,
			LogWrite:  logHandler,
			TLSConfig: tlsConfig,
		}

		smtpsAlive <- true
		err := srv.ListenAndServe()
		if err != nil {
			gologger.Error().Msgf("Could not serve smtp with tls on port %d: %s\n", h.options.SmtpAutoTLSPort, err)
			smtpsAlive <- false
		}
	}()

	smtpAlive <- true
	go func() {
		if err := h.smtpServer.ListenAndServe(); err != nil {
			smtpAlive <- false
			gologger.Error().Msgf("Could not serve smtp on port %d: %s\n", h.options.SmtpPort, err)
		}
	}()
	if err := h.smtpsServer.ListenAndServe(); err != nil {
		gologger.Error().Msgf("Could not serve smtp on port %d: %s\n", h.options.SmtpsPort, err)
		smtpAlive <- false
	}
}

// defaultHandler is a handler for default collaborator requests
func (h *SMTPServer) defaultHandler(remoteAddr net.Addr, from string, to []string, data []byte) error {
	atomic.AddUint64(&h.options.Stats.Smtp, 1)

	var uniqueID, fullID string

	dataString := string(data)
	gologger.Debug().Msgf("New SMTP request: %s %s %s %s\n", remoteAddr, from, to, dataString)

	// Retrieve and format the full SMTP protocol conversation
	host, _, _ := net.SplitHostPort(remoteAddr.String())
	var protocolConversation string
	if conv, ok := h.conversationMap.Load(host); ok {
		c := conv.(*smtpConversation)
		c.mu.Lock()
		protocolConversation = strings.Join(c.lines, "\n")
		c.mu.Unlock()
		// Clean up immediately to prevent stale data in subsequent connections from same IP
		h.conversationMap.Delete(host)
	}

	// if root-tld is enabled stores any interaction towards the main domain
	for _, addr := range to {
		if h.options.RootTLD {
			for _, domain := range h.options.Domains {
				if stringsutil.HasSuffixI(addr, domain) {
					ID := domain
					address := addr[strings.LastIndex(addr, "@"):]
					interaction := &Interaction{
						Protocol:      "smtp",
						UniqueID:      address,
						FullId:        address,
						RawRequest:    dataString,
						RawResponse:   protocolConversation,
						SMTPFrom:      from,
						RemoteAddress: host,
						Timestamp:     time.Now(),
					}
					buffer := &bytes.Buffer{}
					if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
						gologger.Warning().Msgf("Could not encode root tld SMTP interaction: %s\n", err)
					} else {
						gologger.Debug().Msgf("Root TLD SMTP Interaction: \n%s\n", buffer.String())
						if err := h.options.Storage.AddInteractionWithId(ID, buffer.Bytes()); err != nil {
							gologger.Warning().Msgf("Could not store root tld smtp interaction: %s\n", err)
						}
					}
				}
			}
		}
	}

	for _, addr := range to {
		if len(addr) > h.options.GetIdLength() && strings.Contains(addr, "@") {
			parts := strings.Split(addr[strings.LastIndex(addr, "@")+1:], ".")
			for i, part := range parts {
				if h.options.isCorrelationID(part) {
					uniqueID = part
					fullID = part
					if i+1 <= len(parts) {
						fullID = strings.Join(parts[:i+1], ".")
					}
				}
			}
		}
	}
	if uniqueID != "" {
		correlationID := uniqueID[:h.options.CorrelationIdLength]
		interaction := &Interaction{
			Protocol:      "smtp",
			UniqueID:      uniqueID,
			FullId:        fullID,
			RawRequest:    dataString,
			RawResponse:   protocolConversation,
			SMTPFrom:      from,
			RemoteAddress: host,
			Timestamp:     time.Now(),
		}
		buffer := &bytes.Buffer{}
		if err := jsoniter.NewEncoder(buffer).Encode(interaction); err != nil {
			gologger.Warning().Msgf("Could not encode smtp interaction: %s\n", err)
		} else {
			gologger.Debug().Msgf("%s\n", buffer.String())
			if err := h.options.Storage.AddInteraction(correlationID, buffer.Bytes()); err != nil {
				gologger.Warning().Msgf("Could not store smtp interaction: %s\n", err)
			}
		}
	}
	return nil
}
