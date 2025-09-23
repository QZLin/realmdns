package realmdns

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"context"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin(m)

type MDNS struct {
	Next        plugin.Handler
	bindAddress string
	mutex       *sync.RWMutex
}

func (mdns MDNS) ReplaceDomain(input string) string { return input[0 : len(input)-1] }

func (mdns MDNS) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	msg.RecursionAvailable = true
	state := request.Request{W: w, Req: r}

	qName := state.QName()
	fixedName := mdns.ReplaceDomain(qName)
	log.Debugf("Looking for name: %s", qName)

	if !strings.HasSuffix(qName, ".local.") {
		log.Debugf("Skipping due to query '%s' not ending with '.local.'", qName)
		return plugin.NextOrFailure(mdns.Name(), mdns.Next, ctx, w, r)
	}

	if state.QType() != dns.TypeA && state.QType() != dns.TypeAAAA && state.QType() != dns.TypeSRV && state.QType() != dns.TypeCNAME {
		log.Debugf("Skipping due to unrecognized query type %v", state.QType())
		return plugin.NextOrFailure(mdns.Name(), mdns.Next, ctx, w, r)
	}

	msg.Answer = []dns.RR{}

	mdns.mutex.RLock()
	defer mdns.mutex.RUnlock()

	addrList, err := net.LookupHost(fixedName)
	if err != nil {
		log.Errorf("Lookup error: %s", err)
	} else {
		msg.Answer = []dns.RR{}
		qtype := state.QType()
		for _, addr := range addrList {
			// Cleanup ipv6 zone
			cleanAddr := addr
			if strings.Contains(addr, "%") {
				parts := strings.Split(addr, "%")
				cleanAddr = parts[0]
				log.Debugf("Removed zone identifier from %s, using %s", addr, cleanAddr)
			}

			ip := net.ParseIP(cleanAddr)
			if ip == nil {
				log.Warningf("Invalid IP address: %s (cleaned from %s)", cleanAddr, addr)
				continue
			}
			isIpv4 := ip.To4()

			// Add records
			if qtype == dns.TypeA && isIpv4 != nil {
				aRecord := &dns.A{
					Hdr: dns.RR_Header{
						Name:   qName,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: ip,
				}
				msg.Answer = append(msg.Answer, aRecord)
			} else if qtype == dns.TypeAAAA && isIpv4 == nil {
				aaaaRecord := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   qName,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					AAAA: ip,
				}
				msg.Answer = append(msg.Answer, aaaaRecord)
			}
		}
		msg.SetRcode(state.Req, dns.RcodeSuccess)
		msg.Authoritative = true
		msg.RecursionAvailable = true
		log.Debugf("Response message: %s", msg.String())
		err = w.WriteMsg(msg)
		if err != nil {
			log.Errorf("Failed to write response: %s", err)
		}
		return dns.RcodeSuccess, nil
	}
	log.Debugf("No records found for '%s', forwarding to next plugin.", qName)
	return plugin.NextOrFailure(mdns.Name(), mdns.Next, ctx, w, r)
}

func (mdns MDNS) Name() string { return m }

type ResponsePrinter struct {
	dns.ResponseWriter
}

func NewResponsePrinter(w dns.ResponseWriter) *ResponsePrinter {
	return &ResponsePrinter{ResponseWriter: w}
}

func (r *ResponsePrinter) WriteMsg(res *dns.Msg) error {
	_, err := fmt.Fprintln(out, m)
	if err != nil {
		return err
	}
	return r.ResponseWriter.WriteMsg(res)
}

var out io.Writer = os.Stdout
