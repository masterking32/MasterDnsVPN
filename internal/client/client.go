// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import (
	"fmt"
	"strconv"
	"strings"

	"masterdnsvpn-go/internal/config"
	"masterdnsvpn-go/internal/logger"
	"masterdnsvpn-go/internal/security"
)

type Client struct {
	cfg   config.ClientConfig
	log   *logger.Logger
	codec *security.Codec

	connections      []Connection
	connectionsByKey map[string]int

	successMTUChecks bool
	sessionID        uint8
	sessionCookie    uint8
	enqueueSeq       uint64
}

type Connection struct {
	Domain        string
	Resolver      string
	ResolverPort  int
	ResolverLabel string
	Key           string
	IsValid       bool
}

func Bootstrap(configPath string) (*Client, error) {
	cfg, err := config.LoadClientConfig(configPath)
	if err != nil {
		return nil, err
	}

	log := logger.New("MasterDnsVPN Go Client", cfg.LogLevel)
	codec, err := security.NewCodec(cfg.DataEncryptionMethod, cfg.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("client codec setup failed: %w", err)
	}

	c := New(cfg, log, codec)
	c.BuildConnectionMap()
	return c, nil
}

func New(cfg config.ClientConfig, log *logger.Logger, codec *security.Codec) *Client {
	c := &Client{
		cfg:              cfg,
		log:              log,
		codec:            codec,
		connectionsByKey: make(map[string]int, len(cfg.Domains)*len(cfg.Resolvers)),
	}
	c.ResetRuntimeState(true)
	return c
}

func (c *Client) Config() config.ClientConfig {
	return c.cfg
}

func (c *Client) Logger() *logger.Logger {
	return c.log
}

func (c *Client) Codec() *security.Codec {
	return c.codec
}

func (c *Client) Connections() []Connection {
	return c.connections
}

func (c *Client) ResetRuntimeState(resetSessionCookie bool) {
	c.enqueueSeq = 0
	c.sessionID = 0
	if resetSessionCookie {
		c.sessionCookie = 0
	}
}

func (c *Client) BuildConnectionMap() {
	domains := c.cfg.Domains
	resolvers := c.cfg.Resolvers

	total := len(domains) * len(resolvers)
	if total <= 0 {
		c.connections = nil
		c.connectionsByKey = make(map[string]int)
		return
	}

	connections := make([]Connection, 0, total)
	indexByKey := make(map[string]int, total)

	for _, domain := range domains {
		for _, resolver := range resolvers {
			label := formatResolverEndpoint(resolver.IP, resolver.Port)
			key := makeConnectionKey(resolver.IP, resolver.Port, domain)
			if _, exists := indexByKey[key]; exists {
				continue
			}

			indexByKey[key] = len(connections)
			connections = append(connections, Connection{
				Domain:        domain,
				Resolver:      resolver.IP,
				ResolverPort:  resolver.Port,
				ResolverLabel: label,
				Key:           key,
			})
		}
	}

	c.connections = connections
	c.connectionsByKey = indexByKey
}

func formatResolverEndpoint(resolver string, port int) string {
	if strings.IndexByte(resolver, ':') >= 0 && !strings.HasPrefix(resolver, "[") {
		return fmt.Sprintf("[%s]:%d", resolver, port)
	}
	return fmt.Sprintf("%s:%d", resolver, port)
}

func makeConnectionKey(resolver string, port int, domain string) string {
	return resolver + "|" + strconv.Itoa(port) + "|" + domain
}
