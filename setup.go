package realmdns

import (
	"sync"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/coredns/caddy"
)

const m = "realmdns"

func init() {
	caddy.RegisterPlugin(m, caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	c.Next()
	c.NextArg()
	// Note that a filter of "" will match everything
	bindAddress := ""
	if c.NextArg() {
		bindAddress = c.Val()
	}
	if c.NextArg() {
		return plugin.Error(m, c.ArgErr())
	}

	// Because the plugin interface uses a value receiver, we need to make these
	// pointers so all copies of the plugin point at the same maps.
	mutex := sync.RWMutex{}
	mdns := MDNS{bindAddress: bindAddress, mutex: &mutex}

	c.OnStartup(func() error {
		//go browseLoop(&mdns)
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		mdns.Next = next
		return mdns
	})

	return nil
}

/* func browseLoop(m *MDNS) {
	for {
		m.BrowseMDNS()
		// 5 seconds seems to be the minimum ttl that the cache plugin will allow
		// Since each browse operation takes around 2 seconds, this should be fine
		time.Sleep(5 * time.Second)
	}
} */
