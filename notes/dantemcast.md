# Dante Multicast Flow Discovery

## Solution (2026-01-23)

**Problem**: Multicast flows showed `?? (dante-av:xxxxx)` instead of the TX device name.

**Root Cause**: `UpdateDanteTxChannels()` was never being called, so `GetDanteTxDeviceInGroup()` couldn't identify which member of a multicast group was the transmitter.

**Fix**: Added call to `t.nodes.UpdateDanteTxChannels(info.Name, ip, ...)` when a device with TX channels is discovered via ARC protocol.

**How it works now**:
1. TX device discovered via mDNS, probed via ARC (port 4440)
2. ARC query 0x1000 returns TX channel count > 0
3. `UpdateDanteTxChannels()` marks the device as a transmitter
4. IGMP snooping detects TX device joining multicast group
5. IGMP snooping detects RX device joining same multicast group
6. `GetDanteTxDeviceInGroup()` finds the TX device (has TxChannels) in the group
7. Flow displayed as `TX-DEVICE -> RX-DEVICE`

---

## Protocol Notes

### ARC Protocol Packet Formats

There are two packet formats observed:

**Format 1 (0x27xx)** - Used by our code for basic queries:
```
27 xx LL LL 13 xx CC CC 00 00 [args...]
   ^seq     ^0x1300|seq
```

**Format 2 (0x2809)** - Used by Dante Controller:
```
28 09 LL LL SS SS CC CC 00 00 [args...]
      ^len ^seq  ^cmd
```

Basic commands (0x1000, 0x1003, 0x3000) work with Format 1.
Advanced commands (0x2600, 0x3600) require Format 2 to avoid error status 0x0030.

### Commands Tested

| Command | Purpose | Status |
|---------|---------|--------|
| 0x1000 | Channel counts | Works |
| 0x1003 | Device name | Works |
| 0x2000 | TX channel names | Works |
| 0x2010 | TX flow slots | Returns zeros (no flow config) |
| 0x2600 | TX unicast flows | Returns zeros (multicast not included) |
| 0x3000 | RX subscriptions | Works for unicast; multicast has empty TX device |
| 0x3600 | RX unicast source | Returns zeros (multicast not included) |

### 0x2600/0x3600 Unicast Flow Commands

These commands work for **unicast** flows but return empty data for **multicast** flows.

**Query format** (34 bytes):
```
28 09 00 22 SS SS 26 00 00 00
00 00 00 00 00 00 00 00
00 01 00 01 00 01
00 00 00 00 00 00 00 00 00 00
```

**Successful response** (from pcap with active unicast flows):
- 148 bytes with status 0x0001
- Contains MAC address pattern `08 02 10 e2 ef fd XX XX`
- MAC can be correlated between TX (0x2600) and RX (0x3600) devices

**Empty response** (current network with multicast flows):
- 50 bytes with status 0x0001
- Data section shows `10 00` (0 records) instead of `10 01` (1 record)
- No MAC data available

### Multicast vs Unicast

**Unicast flows**: RX device stores TX device name in subscription record (0x3000 response).

**Multicast flows**: RX subscription has empty TX device name. Routing is handled at network layer via IGMP. The Dante device doesn't store "which device is transmitting to me" because multicast is anonymous.

---

## What Works

1. **IGMP correlation** - When TX devices are marked via `UpdateDanteTxChannels()`, we can identify the transmitter in a multicast group by checking which group member has TX channels.

2. **Unicast flow discovery** - 0x3000 returns full TX device name and channel for unicast subscriptions.

3. **Device discovery** - mDNS + ARC protocol reliably discovers all Dante devices.

## What Doesn't Work

1. **MAC-based correlation** - 0x2600/0x3600 return empty data for multicast flows. Only works when unicast flows are active (as seen in pcap from Dante Controller).

2. **Per-channel multicast routing** - We can identify TX device -> RX device at the device level via IGMP, but not individual channel mappings within a multicast flow.

3. **0x2010 flow slots** - Always returns zeros on tested devices (AJA, Shure, A&H).

---

## Pcap Analysis Notes

Captured Dante Controller polling the network. Key findings:

- Dante Controller uses 0x2809 packet format
- Queries many commands we hadn't tried: 0x2320, 0x2400, 0x3300, 0x3400
- 0x2600/0x3600 responses contained MAC addresses when unicast flows were active
- MAC pattern: `08 02` followed by Audinate OUI `10 e2 ef`
- Same MAC in TX's 0x2600 response matches RX's 0x3600 response = flow link

Commands observed (sorted by frequency):
- 0x1000, 0x1003, 0x1100, 0x1102 - Device info
- 0x2000, 0x2010, 0x2032, 0x2204, 0x2320, 0x2400, 0x2600 - TX queries
- 0x3000, 0x3300, 0x3400, 0x3600 - RX queries
