package realmdns

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin(pluginName)

type RealMDNS struct {
	Next        plugin.Handler
	bindAddress string
	mutex       *sync.RWMutex
}

func (realmdns RealMDNS) Greeting() {
	log.Infof("This is %s(%s)", pluginName, pluginVer)
}

func (realmdns RealMDNS) ReplaceDomain(input string) string {
	if len(input) > 0 && input[len(input)-1] == '.' {
		return input[:len(input)-1]
	}
	return input
}

// queryMDNS queries A/AAAA records by sending mDNS packets from a random port
// and multicasting them to 224.0.0.251:5353
func queryMDNS(name string, timeout time.Duration) ([]dns.RR, error) {
	var answers []dns.RR

	// Create a UDP socket with a random port
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer func(conn *net.UDPConn) {
		err := conn.Close()
		if err != nil {

		}
	}(conn)

	types := []uint16{dns.TypeA, dns.TypeAAAA}

	for _, qtype := range types {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		m.RecursionDesired = false
		out, _ := m.Pack()

		dst := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}
		_, err := conn.WriteToUDP(out, dst)
		if err != nil {
			log.Warningf("Failed to send mDNS query: %v", err)
			continue
		}

		// Receive response
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1500)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Debugf("mDNS read timeout or error: %v", err)
			continue
		}

		in := new(dns.Msg)
		if err := in.Unpack(buf[:n]); err != nil {
			log.Debugf("Failed to unpack mDNS response: %v", err)
			continue
		}

		answers = append(answers, in.Answer...)
	}

	return answers, nil
}

func (realmdns RealMDNS) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	msg.RecursionAvailable = true

	state := request.Request{W: w, Req: r}
	qName := state.QName()
	fixedName := realmdns.ReplaceDomain(qName)

	log.Debugf("Looking for name: %s", qName)

	// Only handle queries ending with ".local."
	if !strings.HasSuffix(qName, ".local.") {
		log.Debugf("Skipping query '%s' not ending with '.local.'", qName)
		return plugin.NextOrFailure(realmdns.Name(), realmdns.Next, ctx, w, r)
	}

	// Only handle specific DNS types
	switch state.QType() {
	case dns.TypeA, dns.TypeAAAA, dns.TypeSRV, dns.TypeCNAME, dns.TypePTR:
	default:
		log.Debugf("Skipping unrecognized query type %v", state.QType())
		return plugin.NextOrFailure(realmdns.Name(), realmdns.Next, ctx, w, r)
	}

	msg.Answer = []dns.RR{}
	msg.Extra = []dns.RR{}

	// Perform mDNS query
	answers, err := queryMDNS(fixedName, 2*time.Second)
	if err != nil {
		log.Debugf("mDNS query failed: %v", err)
	}

	// Filter answers based on query type
	for _, ans := range answers {
		switch ans.Header().Rrtype {
		case dns.TypeA:
			if state.QType() == dns.TypeA {
				msg.Answer = append(msg.Answer, ans)
			} else if state.QType() == dns.TypeAAAA {
				msg.Extra = append(msg.Extra, ans)
			}
		case dns.TypeAAAA:
			if state.QType() == dns.TypeAAAA {
				msg.Answer = append(msg.Answer, ans)
			} else if state.QType() == dns.TypeA {
				msg.Extra = append(msg.Extra, ans)
			}
		}
	}

	// Send response if any answer found
	if len(msg.Answer) > 0 {
		msg.SetRcode(state.Req, dns.RcodeSuccess)
		log.Debugf("Sending mDNS response: %s", msg.String())
		if err := w.WriteMsg(msg); err != nil {
			log.Errorf("Failed to write response: %s", err)
		}
		return dns.RcodeSuccess, nil
	}

	log.Debugf("No mDNS records found for '%s', forwarding to next plugin.", qName)
	return plugin.NextOrFailure(realmdns.Name(), realmdns.Next, ctx, w, r)
}

func (realmdns RealMDNS) Name() string { return pluginName }

type ResponsePrinter struct {
	dns.ResponseWriter
}

// WriteMsg prints plugin name before sending the DNS response
func (r *ResponsePrinter) WriteMsg(res *dns.Msg) error {
	_, err := fmt.Fprintln(out, pluginName)
	if err != nil {
		return err
	}
	return r.ResponseWriter.WriteMsg(res)
}

var out io.Writer = os.Stdout
