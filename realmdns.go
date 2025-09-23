package realmdns

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/hashicorp/mdns"
	"github.com/miekg/dns"
)

//const pluginName = "realmdns"

var log = clog.NewWithPlugin(pluginName)

type RealMDNS struct {
	Next        plugin.Handler
	bindAddress string
	mutex       *sync.RWMutex
}

func (realmdns RealMDNS) ReplaceDomain(input string) string {
	if len(input) > 0 && input[len(input)-1] == '.' {
		return input[:len(input)-1]
	}
	return input
}

func (realmdns RealMDNS) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	msg.RecursionAvailable = true

	state := request.Request{W: w, Req: r}
	qName := state.QName()
	//fixedName := realmdns.ReplaceDomain(qName)

	log.Debugf("Looking for name: %s", qName)

	if !strings.HasSuffix(qName, ".local.") {
		log.Debugf("Skipping query '%s' not ending with '.local.'", qName)
		return plugin.NextOrFailure(realmdns.Name(), realmdns.Next, ctx, w, r)
	}

	// Handle only A, AAAA, SRV, CNAME, PTR
	switch state.QType() {
	case dns.TypeA, dns.TypeAAAA, dns.TypeSRV, dns.TypeCNAME, dns.TypePTR:
	default:
		log.Debugf("Skipping unrecognized query type %v", state.QType())
		return plugin.NextOrFailure(realmdns.Name(), realmdns.Next, ctx, w, r)
	}

	msg.Answer = []dns.RR{}

	entriesCh := make(chan *mdns.ServiceEntry, 10)

	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Start lookup in goroutine
	go func() {
		defer close(entriesCh)
		params := &mdns.QueryParam{
			Service:             qName,
			Domain:              "local",
			Entries:             entriesCh,
			WantUnicastResponse: false,
			Timeout:             1 * time.Second,
		}
		_ = mdns.Query(params)
	}()

	var foundRecords bool

Loop:
	for {
		select {
		case <-lookupCtx.Done():
			break Loop
		case entry, ok := <-entriesCh:
			if !ok {
				break Loop
			}
			log.Debugf("Received mDNS entry: %+v", entry)

			// A record
			if state.QType() == dns.TypeA && entry.Addr != nil && entry.Addr.To4() != nil {
				aRecord := &dns.A{
					Hdr: dns.RR_Header{Name: qName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120},
					A:   entry.Addr,
				}
				msg.Answer = append(msg.Answer, aRecord)
				foundRecords = true
			}

			// AAAA record
			if state.QType() == dns.TypeAAAA && entry.AddrV6 != nil && entry.AddrV6.To16() != nil {
				aaaaRecord := &dns.AAAA{
					Hdr:  dns.RR_Header{Name: qName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 120},
					AAAA: entry.AddrV6,
				}
				msg.Answer = append(msg.Answer, aaaaRecord)
				foundRecords = true
			}

			// SRV record
			if state.QType() == dns.TypeSRV && entry.Port > 0 && entry.Host != "" {
				srvRecord := &dns.SRV{
					Hdr:    dns.RR_Header{Name: qName, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120},
					Port:   uint16(entry.Port),
					Target: dns.Fqdn(entry.Host),
				}
				msg.Answer = append(msg.Answer, srvRecord)
				foundRecords = true
			}

			// PTR record
			if state.QType() == dns.TypePTR && entry.Name != "" {
				ptrRecord := &dns.PTR{
					Hdr: dns.RR_Header{Name: qName, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120},
					Ptr: dns.Fqdn(entry.Name),
				}
				msg.Answer = append(msg.Answer, ptrRecord)
				foundRecords = true
			}
		}
	}

	if foundRecords {
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

func (r *ResponsePrinter) WriteMsg(res *dns.Msg) error {
	_, err := fmt.Fprintln(out, pluginName)
	if err != nil {
		return err
	}
	return r.ResponseWriter.WriteMsg(res)
}

var out io.Writer = os.Stdout
