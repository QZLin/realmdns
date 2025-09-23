package realmdns

import (
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

	"github.com/celebdor/zeroconf"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

var log = clog.NewWithPlugin("realmdns")

type MDNS struct {
	Next        plugin.Handler
	Domain      string
	minSRV      int
	filter      string
	bindAddress string
	mutex       *sync.RWMutex
	mdnsHosts   *map[string]*zeroconf.ServiceEntry
	srvHosts    *map[string][]*zeroconf.ServiceEntry
	cnames      *map[string]string
}

func (m MDNS) ReplaceDomain(input string) string {
	//// Replace input domain with our configured custom domain
	//fqDomain := "." + strings.TrimSuffix(m.Domain, ".") + "."
	//domainParts := strings.SplitN(input, ".", 2)
	//// +1 so we strip the leading . as well
	//suffixLen := len(domainParts[1]) + 1
	//return input[0:len(input)-suffixLen] + fqDomain
	return input[0 : len(input)-1]
}

func (m MDNS) AddARecord(msg *dns.Msg, state *request.Request, hosts map[string]*zeroconf.ServiceEntry, name string) bool {
	// Add A and AAAA record for name (if it exists) to msg.
	// A records need to be returned in both A and CNAME queries, this function
	// provides common code for doing so.
	answerEntry, present := hosts[name]
	if present {
		if answerEntry.AddrIPv4 != nil {
			aheader := dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}
			// TODO: Support multiple addresses
			msg.Answer = append(msg.Answer, &dns.A{Hdr: aheader, A: answerEntry.AddrIPv4[0]})
		}
		if answerEntry.AddrIPv6 != nil {
			aaaaheader := dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}
			msg.Answer = append(msg.Answer, &dns.AAAA{Hdr: aaaaheader, AAAA: answerEntry.AddrIPv6[0]})
		}
		return true
	}
	return false
}

// Return the node index from a hostname.
// For example, the return value from "master-0.ostest.test.metal3.io" would be "0"
func GetIndex(host string) string {
	shortname := strings.Split(host, ".")[0]
	return shortname[strings.LastIndex(shortname, "-")+1:]
}

func (m MDNS) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	//log.Debug("Received query")
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	msg.RecursionAvailable = true
	state := request.Request{W: w, Req: r}
	fixed_name := m.ReplaceDomain(state.QName())
	log.Debugf("Looking for name: %s", state.QName())

	if !strings.HasSuffix(state.QName(), ".local.") {
		log.Debugf("Skipping due to query '%s' not ending with '.local.'", state.QName())
		return plugin.NextOrFailure(m.Name(), m.Next, ctx, w, r)
	}

	if state.QType() != dns.TypeA && state.QType() != dns.TypeAAAA && state.QType() != dns.TypeSRV && state.QType() != dns.TypeCNAME {
		log.Debugf("Skipping due to unrecognized query type %v", state.QType())
		return plugin.NextOrFailure(m.Name(), m.Next, ctx, w, r)
	}

	msg.Answer = []dns.RR{}

	m.mutex.RLock()
	defer m.mutex.RUnlock()

	addrs, err := net.LookupHost(fixed_name)
	if err != nil {
		log.Errorf("Lookup error: %s", err)
	} else {
		msg.Answer = []dns.RR{} // 清空可能存在的现有答案
		qtype := state.QType()
		for _, addr := range addrs {
			// 处理IPv6地址中的区域标识
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
			// 根据查询类型和IP地址类型创建相应的DNS记录
			if qtype == dns.TypeA && ip.To4() != nil {
				// 查询A记录且是IPv4地址
				aRecord := &dns.A{
					Hdr: dns.RR_Header{
						Name:   state.QName(),
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: ip,
				}
				msg.Answer = append(msg.Answer, aRecord)
			} else if qtype == dns.TypeAAAA && ip.To4() == nil {
				// 查询AAAA记录且是IPv6地址
				aaaaRecord := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   state.QName(),
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
	log.Debugf("No records found for '%s', forwarding to next plugin.", state.QName())
	return plugin.NextOrFailure(m.Name(), m.Next, ctx, w, r)
}

func (m *MDNS) BrowseMDNS() {
	entriesCh := make(chan *zeroconf.ServiceEntry)
	srvEntriesCh := make(chan *zeroconf.ServiceEntry)
	mdnsHosts := make(map[string]*zeroconf.ServiceEntry)
	srvHosts := make(map[string][]*zeroconf.ServiceEntry)
	cnames := make(map[string]string)
	go func(results <-chan *zeroconf.ServiceEntry) {
		log.Debug("Retrieving mDNS entries")
		for entry := range results {
			// Make a copy of the entry so zeroconf can't later overwrite our changes
			localEntry := *entry
			log.Debugf("A Instance: %s, HostName: %s, AddrIPv4: %s, AddrIPv6: %s\n", localEntry.Instance, localEntry.HostName, localEntry.AddrIPv4, localEntry.AddrIPv6)
			if strings.Contains(localEntry.Instance, m.filter) {
				// Hacky - coerce .local to our domain
				// I was having trouble using domains other than .local. Need further investigation.
				// After further investigation, maybe this is working as intended:
				// https://lists.freedesktop.org/archives/avahi/2006-ebruary/000517.html
				hostCustomDomain := m.ReplaceDomain(localEntry.HostName)
				//hostCustomDomain := localEntry.HostName
				mdnsHosts[hostCustomDomain] = entry
			} else {
				log.Debugf("Ignoring entry '%s' because it doesn't match filter '%s'\n",
					localEntry.Instance, m.filter)
			}
		}
	}(entriesCh)

	go func(results <-chan *zeroconf.ServiceEntry) {
		log.Debug("Retrieving SRV mDNS entries")
		for entry := range results {
			// Make a copy of the entry so mdns can't later overwrite our changes
			localEntry := *entry
			log.Debugf("SRV Instance: %s, Service: %s, Domain: %s, HostName: %s, AddrIPv4: %s, AddrIPv6: %s\n", localEntry.Instance, localEntry.Service, localEntry.Domain, localEntry.HostName, localEntry.AddrIPv4, localEntry.AddrIPv6)
			if strings.Contains(localEntry.Instance, m.filter) {
				localEntry.HostName = m.ReplaceDomain(localEntry.HostName)
				//localEntry.HostName = localEntry.HostName
				srvName := localEntry.Service + "." + m.Domain + "."
				srvHosts[srvName] = append(srvHosts[srvName], &localEntry)
			} else {
				log.Debugf("Ignoring entry '%s' because it doesn't match filter '%s'\n",
					localEntry.Instance, m.filter)
			}
		}
	}(srvEntriesCh)

	var iface net.Interface
	//if m.bindAddress != "" {
	//	foundIface, err := publisher.FindIface(net.ParseIP(m.bindAddress))
	//	if err != nil {
	//		log.Errorf("Failed to find interface for '%s'\n", m.bindAddress)
	//	} else {
	//		iface = foundIface
	//	}
	//}
	_ = queryService("_workstation._tcp", entriesCh, iface, ZeroconfImpl{})
	_ = queryService("_etcd-server-ssl._tcp", srvEntriesCh, iface, ZeroconfImpl{})

	m.mutex.Lock()
	defer m.mutex.Unlock()
	// Clear maps so we don't have stale entries
	for k := range *m.mdnsHosts {
		delete(*m.mdnsHosts, k)
	}
	for k := range *m.srvHosts {
		delete(*m.srvHosts, k)
	}
	for k := range *m.cnames {
		delete(*m.cnames, k)
	}
	// Copy values into the shared maps only after we've collected all of them.
	// This prevents us from having to lock during the entire mdns browse time.
	for k, v := range mdnsHosts {
		(*m.mdnsHosts)[k] = v
	}
	for k, v := range srvHosts {
		// Don't return any SRV records until we have enough of them. Returning
		// partial SRV lists can result in bad clustering.
		if len(v) >= m.minSRV {
			(*m.srvHosts)[k] = v
		}
	}
	for k, v := range cnames {
		(*m.cnames)[k] = v
	}
	log.Infof("mdnsHosts: %v", m.mdnsHosts)
	for name, entry := range *m.mdnsHosts {
		log.Debugf("%s: %v", name, entry)
	}
	log.Debugf("srvHosts: %v", m.srvHosts)
	for name, records := range *m.srvHosts {
		for _, v := range records {
			log.Debugf("%s: %v", name, v)
		}
	}
	log.Debugf("cnames: %v", m.cnames)
}

func queryService(service string, channel chan *zeroconf.ServiceEntry, iface net.Interface, z ZeroconfInterface) error {
	var opts zeroconf.ClientOption
	if iface.Name != "" {
		opts = zeroconf.SelectIfaces([]net.Interface{iface})
	}
	resolver, err := z.NewResolver(opts)
	if err != nil {
		log.Errorf("Failed to initialize %s resolver: %s", service, err.Error())
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = resolver.Browse(ctx, service, "local.", channel)
	if err != nil {
		log.Errorf("Failed to browse %s records: %s", service, err.Error())
		return err
	}
	<-ctx.Done()
	return nil
}

func (m MDNS) Name() string { return "realmdns" }

type ResponsePrinter struct {
	dns.ResponseWriter
}

func NewResponsePrinter(w dns.ResponseWriter) *ResponsePrinter {
	return &ResponsePrinter{ResponseWriter: w}
}

func (r *ResponsePrinter) WriteMsg(res *dns.Msg) error {
	fmt.Fprintln(out, m)
	return r.ResponseWriter.WriteMsg(res)
}

var out io.Writer = os.Stdout

type ZeroconfInterface interface {
	NewResolver(...zeroconf.ClientOption) (ResolverInterface, error)
}

type ZeroconfImpl struct{}

func (z ZeroconfImpl) NewResolver(opts ...zeroconf.ClientOption) (ResolverInterface, error) {
	return zeroconf.NewResolver(opts...)
}

type ResolverInterface interface {
	Browse(context.Context, string, string, chan<- *zeroconf.ServiceEntry) error
}

const m = "realmdns"
