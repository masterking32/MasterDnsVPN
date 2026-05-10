// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the MasterDnsVPN client.
// This file (mtu_logging.go) handles logging for MTU testing.
// ==============================================================================
package client

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"masterdnsvpn-go/internal/logger"
)

const (
	defaultMTUServersFileFormat = "{IP} - UP: {UP_MTU} DOWN: {DOWN-MTU}"
)

type mtuLogFields struct {
	resolverLabel string
	domain        string
	uploadMTU     int
	downloadMTU   int
	uploadChars   int
}

func (c *Client) mtuDebugEnabled() bool {
	return c != nil && c.log != nil && c.log.Enabled(logger.LevelDebug)
}

func (c *Client) mtuInfoEnabled() bool {
	return c != nil && c.log != nil && c.log.Enabled(logger.LevelInfo)
}

func (c *Client) mtuWarnEnabled() bool {
	return c != nil && c.log != nil && c.log.Enabled(logger.LevelWarn)
}

func (c *Client) logMTUProbe(isRetry bool, background bool, format string, args ...any) {
	if isRetry || background || !c.mtuDebugEnabled() {
		return
	}
	c.log.Debugf(format, args...)
}

func (c *Client) logMTUStart(workerCount int) {
	if !c.mtuInfoEnabled() {
		return
	}
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<yellow>Testing MTU sizes for all resolver-domain pairs (parallel=%d)...</yellow>",
		workerCount,
	)
}

func (c *Client) logMTUCompletion(validConns []Connection) {
	if !c.mtuInfoEnabled() {
		return
	}

	totalResolvers := c.mtuTotalResolverCount(validConns)

	maxFoundUpload := 0
	maxFoundDownload := 0
	for _, conn := range validConns {
		if conn.UploadMTUBytes > maxFoundUpload {
			maxFoundUpload = conn.UploadMTUBytes
		}
		if conn.DownloadMTUBytes > maxFoundDownload {
			maxFoundDownload = conn.DownloadMTUBytes
		}
	}

	c.log.Infof("<green>MTU Testing Completed!</green>")
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof("<cyan>Valid Connections After MTU Testing:</cyan>")
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"%-20s %-15s %-15s %-14s %-30s",
		"Resolver",
		"Upload MTU",
		"Download MTU",
		"Resolve Time",
		"Domain",
	)

	c.log.Infof("%s", strings.Repeat("-", 80))
	for _, conn := range validConns {
		resolveTime := "n/a"
		if conn.MTUResolveTime > 0 {
			resolveTime = formatResolverRTT(conn.MTUResolveTime)
		}

		c.log.Infof(
			"<cyan>%-20s</cyan> <green>%-15d</green> <green>%-15d</green> <yellow>%-14s</yellow> <blue>%-30s</blue>",
			conn.ResolverLabel,
			conn.UploadMTUBytes,
			conn.DownloadMTUBytes,
			resolveTime,
			conn.Domain,
		)
	}
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<blue>Total valid resolvers after MTU testing: <cyan>%d</cyan> of <cyan>%d</cyan></blue>",
		len(validConns),
		totalResolvers,
	)
	c.log.Infof(
		"<blue>Note:</blue> Each packet will be sent <yellow>%d</yellow> times to improve reliability.",
		c.cfg.PacketDuplicationCount,
	)

	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<cyan>[MTU RESULTS]</cyan> Max Upload MTU found: <yellow>%d</yellow> | Max Download MTU found: <yellow>%d</yellow>",
		maxFoundUpload,
		maxFoundDownload,
	)
	c.log.Infof(
		"<cyan>[MTU RESULTS]</cyan> Selected Synced Upload MTU: <yellow>%d</yellow> | Selected Synced Download MTU: <yellow>%d</yellow>",
		c.syncedUploadMTU,
		c.syncedDownloadMTU,
	)
	c.log.Infof("%s", strings.Repeat("=", 80))
	c.log.Infof(
		"<green>Global MTU Configuration -> Upload: <cyan>%d</cyan>, Download: <cyan>%d</cyan></green>",
		c.syncedUploadMTU,
		c.syncedDownloadMTU,
	)
}

func (c *Client) mtuTotalResolverCount(validConns []Connection) int {
	if c != nil && c.balancer != nil {
		return c.balancer.TotalCount()
	}
	return len(validConns)
}

func formatResolverRTT(rtt time.Duration) string {
	if rtt <= 0 {
		return "n/a"
	}

	if rtt < time.Millisecond {
		return "<1ms"
	}

	return rtt.Round(time.Millisecond).String()
}

func (c *Client) resolveMTUSuccessOutputPath() string {
	if c == nil || !c.mtuSaveToFile {
		return ""
	}

	rawName := strings.TrimSpace(c.mtuServersFileName)
	if rawName == "" {
		if c.mtuWarnEnabled() {
			c.log.Warnf(
				"<yellow>[MTU]</yellow> MTU result saving is enabled, but <cyan>MTU_SERVERS_FILE_NAME</cyan> is empty.",
			)
		}
		return ""
	}

	if strings.Contains(rawName, "{time}") {
		ts := c.now().Format("20060102_150405")
		baseName := strings.TrimSpace(strings.ReplaceAll(rawName, "{time}", ""))
		if baseName == "" {
			baseName = "masterdnsvpn_success_test"
		}
		ext := filepath.Ext(baseName)
		root := strings.TrimSuffix(baseName, ext)
		if root == "" {
			root = baseName
		}
		if ext == "" {
			ext = ".log"
		}
		rawName = root + "_" + ts + ext
	}

	if !filepath.IsAbs(rawName) {
		rawName = filepath.Join(c.cfg.ConfigDir, rawName)
	}
	return filepath.Clean(rawName)
}

func (c *Client) prepareMTUSuccessOutputFile() string {
	if c == nil || !c.mtuSaveToFile {
		return ""
	}

	outputPath := c.resolveMTUSuccessOutputPath()
	c.mtuOutputMu.Lock()
	c.mtuUsageSeparatorWritten = false
	c.mtuSuccessOutputPath = ""
	c.mtuOutputMu.Unlock()
	if outputPath == "" {
		return ""
	}

	if err := c.initializeMTUSuccessOutputFile(outputPath); err != nil {
		c.warnMTUOutputError(outputPath, err)
		return ""
	}

	c.mtuOutputMu.Lock()
	c.mtuSuccessOutputPath = outputPath
	c.mtuOutputMu.Unlock()

	if c.mtuInfoEnabled() {
		c.log.Infof(
			"<blue>[MTU]</blue> Success output file initialized: <cyan>%s</cyan>",
			outputPath,
		)
	}
	return outputPath
}

func (c *Client) initializeMTUSuccessOutputFile(outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	return os.WriteFile(outputPath, []byte{}, 0o644)
}

func (c *Client) warnMTUOutputError(outputPath string, err error) {
	if !c.mtuWarnEnabled() {
		return
	}

	c.log.Warnf(
		"<yellow>[MTU]</yellow> Failed to initialize output file <cyan>%s</cyan>: %v",
		outputPath,
		err,
	)
}

func mtuFieldsFromConnection(conn *Connection) mtuLogFields {
	if conn == nil {
		return mtuLogFields{}
	}

	return mtuLogFields{
		resolverLabel: conn.ResolverLabel,
		domain:        conn.Domain,
		uploadMTU:     conn.UploadMTUBytes,
		downloadMTU:   conn.DownloadMTUBytes,
		uploadChars:   conn.UploadMTUChars,
	}
}

func (c *Client) formatMTULogLine(template string, conn *Connection, cause string) string {
	if c == nil {
		return ""
	}
	template = strings.TrimSpace(template)
	if template == "" {
		return ""
	}

	fields := mtuFieldsFromConnection(conn)

	nowText := c.now().Format("2006-01-02 15:04:05")
	line := template
	replacements := []struct {
		token string
		value string
	}{
		{token: "{IP}", value: fields.resolverLabel},
		{token: "{ip}", value: fields.resolverLabel},
		{token: "{RESOLVER}", value: fields.resolverLabel},
		{token: "{resolver}", value: fields.resolverLabel},
		{token: "{DOMAIN}", value: fields.domain},
		{token: "{domain}", value: fields.domain},
		{token: "{UP_MTU}", value: strconv.Itoa(fields.uploadMTU)},
		{token: "{up_mtu}", value: strconv.Itoa(fields.uploadMTU)},
		{token: "{DOWN_MTU}", value: strconv.Itoa(fields.downloadMTU)},
		{token: "{down_mtu}", value: strconv.Itoa(fields.downloadMTU)},
		{token: "{DOWN-MTU}", value: strconv.Itoa(fields.downloadMTU)},
		{token: "{down-mtu}", value: strconv.Itoa(fields.downloadMTU)},
		{token: "{UP_MTU_CHARS}", value: strconv.Itoa(fields.uploadChars)},
		{token: "{up_mtu_chars}", value: strconv.Itoa(fields.uploadChars)},
		{token: "{CAUSE}", value: cause},
		{token: "{cause}", value: cause},
		{token: "{TIME}", value: nowText},
		{token: "{time}", value: nowText},
	}
	for _, item := range replacements {
		line = strings.ReplaceAll(line, item.token, item.value)
	}
	return strings.TrimSpace(line)
}

func (c *Client) appendMTULogLine(template string, conn *Connection, cause string) {
	if c == nil || !c.mtuSaveToFile {
		return
	}

	c.mtuOutputMu.Lock()
	outputPath := c.mtuSuccessOutputPath
	c.mtuOutputMu.Unlock()
	if outputPath == "" {
		return
	}

	line := c.formatMTULogLine(template, conn, cause)
	if line == "" {
		return
	}

	c.mtuOutputMu.Lock()
	defer c.mtuOutputMu.Unlock()

	// Re-check path under lock in case a concurrent session reset cleared it.
	if c.mtuSuccessOutputPath == "" {
		return
	}
	outputPath = c.mtuSuccessOutputPath

	file, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		c.warnMTUAppendError(err)
		return
	}
	defer file.Close()
	if _, err := file.WriteString(line + "\n"); err != nil {
		c.warnMTUAppendError(err)
	}
}

func (c *Client) warnMTUAppendError(err error) {
	if !c.mtuWarnEnabled() {
		return
	}
	c.log.Warnf(
		"<yellow>[MTU]</yellow> Failed to append custom runtime line: %v",
		err,
	)
}

func (c *Client) appendMTUSuccessLine(conn *Connection) {
	if c == nil {
		return
	}
	template := c.mtuServersFileFormat
	if template == "" {
		template = defaultMTUServersFileFormat
	}
	c.appendMTULogLine(template, conn, "")
}

func (c *Client) appendMTUUsageSeparatorOnce() {
	if c == nil {
		return
	}
	c.mtuOutputMu.Lock()
	if c.mtuUsageSeparatorWritten || c.mtuUsingSeparatorText == "" || c.mtuSuccessOutputPath == "" {
		c.mtuOutputMu.Unlock()
		return
	}
	c.mtuUsageSeparatorWritten = true
	template := c.mtuUsingSeparatorText
	c.mtuOutputMu.Unlock()
	c.appendMTULogLine(template, nil, "")
}

func (c *Client) appendMTURemovedServerLine(conn *Connection, cause string) {
	if c == nil || c.mtuRemovedServerLogFormat == "" {
		return
	}

	c.appendMTULogLine(c.mtuRemovedServerLogFormat, conn, cause)
}

func (c *Client) appendMTUAddedServerLine(conn *Connection) {
	if c == nil || c.mtuAddedServerLogFormat == "" {
		return
	}
	c.appendMTULogLine(c.mtuAddedServerLogFormat, conn, "")
}

func (c *Client) appendMTUReactiveAddedServerLine(conn *Connection) {
	if c == nil || c.mtuReactiveAddedServerLogFormat == "" {
		return
	}
	c.appendMTULogLine(c.mtuReactiveAddedServerLogFormat, conn, "")
}
