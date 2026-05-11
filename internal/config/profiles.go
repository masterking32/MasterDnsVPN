// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package config

import (
	"fmt"
	"reflect"
	"strings"
)

// profileOverrides is the per-preset bag of optional overrides. A nil pointer
// means "this preset has no opinion on this knob"; any non-nil pointer is
// applied to ClientConfig only when the matching TOML key was NOT explicitly
// set by the operator. Field names MUST match ClientConfig field names exactly
// — the apply step pairs them by reflection.
type profileOverrides struct {
	ResolverBalancingStrategy      *int
	PacketDuplicationCount         *int
	BaseEncodeData                 *bool
	UploadCompressionType          *int
	DownloadCompressionType        *int
	LocalDNSCacheMaxRecords        *int
	MinUploadMTU                   *int
	MinDownloadMTU                 *int
	MaxUploadMTU                   *int
	MaxDownloadMTU                 *int
	PingAggressiveIntervalSeconds  *float64
	PingLazyIntervalSeconds        *float64
	PingCooldownIntervalSeconds    *float64
	PingColdIntervalSeconds        *float64
	PingWarmThresholdSeconds       *float64
	PingCoolThresholdSeconds       *float64
	PingColdThresholdSeconds       *float64
	ARQInitialRTOSeconds           *float64
	ARQDataNackInitialDelaySeconds *float64
	ARQMaxDataRetries              *int
}

// profilePresets is the registry of named profiles. "stable" is a deliberate
// no-op so operators can pin to it explicitly without changing behavior.
// "" and "custom" are also accepted as no-ops in applyProfile.
var profilePresets = map[string]profileOverrides{
	"stable": {},
}

func applyProfile(cfg *ClientConfig, defined map[string]bool) error {
	if cfg == nil {
		return nil
	}
	name := strings.ToLower(strings.TrimSpace(cfg.Profile))
	cfg.Profile = name
	switch name {
	case "", "custom":
		return nil
	}

	overrides, ok := profilePresets[name]
	if !ok {
		return fmt.Errorf("unknown PROFILE: %q", name)
	}

	src := reflect.ValueOf(overrides)
	srcType := src.Type()
	dst := reflect.ValueOf(cfg).Elem()
	for i := 0; i < src.NumField(); i++ {
		fieldValue := src.Field(i)
		if fieldValue.Kind() != reflect.Ptr || fieldValue.IsNil() {
			continue
		}
		fieldName := srcType.Field(i).Name
		if defined[fieldName] {
			continue
		}
		target := dst.FieldByName(fieldName)
		if !target.IsValid() || !target.CanSet() {
			return fmt.Errorf("profile %q references unknown ClientConfig field %s", name, fieldName)
		}
		target.Set(fieldValue.Elem())
	}
	return nil
}

func intPtr(v int) *int            { return &v }
func boolPtr(v bool) *bool         { return &v }
func floatPtr(v float64) *float64  { return &v }
