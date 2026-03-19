// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package client

import "time"

const runtimeConnectionFanout = 3
const defaultRuntimeTimeout = 5 * time.Second

func normalizeTimeout(timeout time.Duration, fallback time.Duration) time.Duration {
	if timeout <= 0 {
		if fallback > 0 {
			return fallback
		}
		return defaultRuntimeTimeout
	}
	return timeout
}

func (c *Client) runtimeConnections(connections []Connection) ([]Connection, error) {
	if len(connections) != 0 {
		return connections, nil
	}
	connections = c.GetUniqueConnections(runtimeConnectionFanout)
	if len(connections) == 0 {
		return nil, ErrNoValidConnections
	}
	return connections, nil
}

func tryConnections[T any](connections []Connection, fallbackErr error, fn func(Connection) (T, error)) (T, error) {
	var zero T
	lastErr := fallbackErr
	for _, connection := range connections {
		value, err := fn(connection)
		if err == nil {
			return value, nil
		}
		lastErr = err
	}
	return zero, lastErr
}
