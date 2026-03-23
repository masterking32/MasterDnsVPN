// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package vpnproto

// CalculateMaxPackedBlocks calculates the optimal number of control blocks that can be
// packed into a single VPN packet based on the MTU, a safety percentage, and an absolute maximum.
// Each packed control block is 7 bytes: Type(1) + StreamID(2) + SeqNum(2) + FragID(1) + TotalFragments(1).
func CalculateMaxPackedBlocks(mtu int, percent int, absoluteMax int) int {
	if mtu <= 0 {
		return 1
	}

	if percent <= 0 {
		percent = 50 // Default to 50% if invalid percent provided
	}

	effectiveSize := (mtu * percent) / 100

	count := max(min(max(effectiveSize/PackedControlBlockSize, 1), absoluteMax), 1)

	return count
}
