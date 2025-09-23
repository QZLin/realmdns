package realmdns

import (
	"sync"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/coredns/caddy"
)

const pluginName = "realmdns"

func init() {
	caddy.RegisterPlugin(pluginName, caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	c.Next()
	c.NextArg()
	bindAddress := ""
	if c.NextArg() {
		bindAddress = c.Val()
	}
	if c.NextArg() {
		return plugin.Error(pluginName, c.ArgErr())
	}

	// Because the plugin interface uses a value receiver, we need to make these
	// pointers so all copies of the plugin point at the same maps.
	mutex := sync.RWMutex{}
	mdns := RealMDNS{bindAddress: bindAddress, mutex: &mutex}

	c.OnStartup(func() error {
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		mdns.Next = next
		return mdns
	})

	return nil
}
