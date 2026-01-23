# Dante Multicast Flow Discovery Investigation

## Context for Continuation
**Goal**: Find the Dante protocol command that reveals TX channel -> multicast flow -> RX channel mapping.

**Current state**: Receiver's 0x3000 response shows multicast subscriptions with empty TX device name. We've probed 50+ commands on ARC port 4440 and found nothing. IGMP shows device->group membership but NOT per-channel routing.

**Key files modified**:
- `dante_control.go`: Added multicast record parsing, TX channel parsing
- `dante.go`: Added `listenDanteAudio()` stub
- `dantemcast.md`: This file

**Next to try**:
1. Probe TX device for "which of my channels are in multicast flows" command
2. Check if 0x2010/0x2012 need different arguments (flow ID?)
3. Look for SAP/SDP on port 9875
4. Capture Dante Controller traffic with Wireshark to see what it queries

**User instruction**: "stop giving up; we're not stopping until we fix this"

---

## Problem Statement
When Dante devices use multicast flows, the receiver's subscription response (0x3000) returns empty TX device names. We need to find the protocol command that reveals which TX device is transmitting to which multicast flow, so we can display proper flow routing like:
```
AJA-4K-T-022b9c[01] -> AJA-4K-R-023232[01]
```
Instead of:
```
?? (dante-av:xxxxx) -> AJA-4K-R-023232
```

## What We Know

### Receiver Side (0x3000 command)
- Unicast subscriptions (type 0x0006): Include TX device name and channel name
- Multicast subscriptions (type 0x000e): TX device offset points to null (offset 172 = `0000bb80...`)
- Multicast record structure (20 bytes):
  ```
  Offset 0-1:   RX channel number
  Offset 2-3:   Record type (0x000e = multicast)
  Offset 4-5:   TX device name offset (always 172, points to null)
  Offset 6-7:   0x0000 (unknown, always zero)
  Offset 8-9:   0x0000 (unknown, always zero)
  Offset 10-11: TX channel name offset (points to "01", "02", etc.)
  Offset 12-19: 0x00000000 0x00000000 (unknown, always zero)
  ```

### Transmitter Side
- 0x2000: Returns TX channel list with names and flags (0x0105 or 0x0107)
- 0x2002: Returns 272 bytes (8ch) or 168 bytes (4ch) of channel config (sample rate, format, etc.)
- 0x2010: Returns 76 bytes with 8 flow slots, but all zeros
- 0x2011: Returns 16 bytes, small status response
- 0x2012: Returns 76 bytes with 8 flow slots, but all zeros

## Commands Probed (No Multicast Flow Info Found)

### ARC Port (4440)
| Command | Response | Content |
|---------|----------|---------|
| 0x1000 | 44-48 bytes | Channel counts (RX/TX) |
| 0x1001 | varies | Set/reset device name |
| 0x1002 | 24-26 bytes | Device name string |
| 0x1003 | 130-142 bytes | Device info (name, platform) |
| 0x1100 | 16 bytes | Status info |
| 0x2000 | 72-116 bytes | TX channel names |
| 0x2002 | 168-272 bytes | TX channel config (sample rate, format) |
| 0x2010 | 76 bytes | 8 flow slots, all zeros |
| 0x2011 | 16 bytes | Status |
| 0x2012 | 76 bytes | 8 flow slots, all zeros |
| 0x2013 | varies | Set TX channel name |
| 0x2100-0x2500 | varies | Mostly zeros or no response |
| 0x3000 | 60-212 bytes | RX subscriptions (multicast has empty txDev) |
| 0x3001 | varies | Set RX channel name |
| 0x3002-0x300f | 10-12 bytes | Small status responses |
| 0x3010 | varies | Add subscription |
| 0x3014 | varies | Remove subscription |
| 0x4000-0x5000 | no response | Not implemented on these devices |

### CMC Port (8800) and DBC Port (4455)
- No responses from AJA or ULXD4Q devices on these ports
- These ports may only be available on certain device types

## External Resources Checked

### netaudio Python Library
- Located at `/opt/homebrew/lib/python3.14/site-packages/netaudio/dante/`
- Commands implemented: 0x1000, 0x1001, 0x1002, 0x1003, 0x1101, 0x2000, 0x2010, 0x2013, 0x3000, 0x3001, 0x3010, 0x3014
- No multicast flow configuration commands found

### network-audio-controller Wiki
- Confirms protocol is undocumented and reverse-engineered
- No multicast flow commands documented

### Inferno Project (Rust)
- Claims partial TX multicast support but source not accessible
- "Dante protocol is undocumented. Everything was reverse-engineered"

## Current Hypotheses

1. **Flow info stored only at creation time**: Dante Controller may store the flow mapping in its own database when flows are created, not query it from devices.

2. **Info in a different protocol**: Multicast flow config might be managed via:
   - SAP/SDP announcements (standard AES67 mechanism)
   - Dante Domain Manager protocol
   - A different UDP port we haven't found

3. **Info derived from network traffic**: Dante Controller might correlate:
   - TX devices advertising channels via mDNS `_netaudio-chan._udp`
   - IGMP group membership from switches
   - Actual multicast packet sources (sniffing)

## Next Steps to Try

### 1. Sniff Actual Multicast Audio Traffic
Added `listenDanteAudio()` function to capture packets on 239.255.0.0:4321. This would reveal:
- Source IP = TX device
- Destination IP = multicast group

But `ListenMulticastUDP` only joins one specific group. Need to either:
- Use raw sockets / pcap to see all multicast traffic
- Join multiple multicast groups dynamically based on IGMP data

### 2. Try Different Multicast Addresses
Dante uses various multicast ranges:
- 239.255.x.x - Dante AV flows
- 239.253.x.x - Dante audio (older?)
- 224.0.0.x - PTP, mDNS

### 3. Check SAP/SDP
AES67-compatible flows use SAP announcements on 239.255.255.255:9875 or 224.2.127.254:9875. Try listening for SDP session descriptions that might include flow routing.

### 4. Capture Dante Controller Traffic
Run Wireshark while Dante Controller is open to see what protocol it uses. Look for:
- Different UDP ports
- Different command IDs
- TCP connections

### 5. Query via TCP
Some Dante services use TCP. Try connecting to:
- Port 4440 via TCP
- Port 8700-8800 via TCP

### 6. Probe Command Arguments More Thoroughly
Try 0x2010/0x2012 with different argument patterns:
- Flow ID as argument
- Channel number as argument
- Page numbers beyond 1

## Test Devices
- AJA-4K-T-* (10.50.17.6, 10.50.17.24, 10.50.17.28, etc.) - 8ch TX, multicast transmitters
- AJA-4K-R-* (10.50.17.2, 10.50.17.29, 10.50.19.7, etc.) - 8ch RX, multicast receivers
- ULXD4Q-* (10.50.17.4, 10.50.17.5, 10.50.17.7, etc.) - 4ch TX, Shure wireless
- SQ-7 - Mixer, unicast TX (subscriptions show proper device name)

## Code Changes Made
- `dante_control.go`: Added detailed multicast record parsing, TX channel flag parsing
- `dante.go`: Added `listenDanteAudio()` stub for packet capture

## Key Insight
The unicast subscription "06@SQ-7" works correctly because the receiver stores the TX device name. Multicast subscriptions appear to be "anonymous" at the receiver level - the receiver knows which channel from which flow, but not which device is transmitting that flow.

## Why IGMP + mDNS Is Insufficient
Even if we correlate:
- IGMP: TX device 10.50.17.24 is in multicast group 239.253.127.115
- IGMP: RX device 10.50.17.29 is also in multicast group 239.253.127.115
- mDNS: TX device has channels "01" through "08"

We STILL don't know:
1. **Which TX channels** are being sent to that multicast group (could be all 8, could be just 2)
2. **Which TX channel maps to which RX channel** (TX ch1 -> RX ch1? or TX ch3 -> RX ch1?)
3. **Channel-level routing** within the flow

The RX subscription shows "subscribed to channel 01 from multicast" but not "subscribed to channel 01 from AJA-4K-T-022fde". The per-channel TX->RX mapping through multicast is the missing piece.

Dante Controller DOES show this info, so there must be a way to query it. Possibilities:
1. A command we haven't found that returns "TX channel X is in multicast flow Y"
2. The TX device stores which of its channels are in multicast flows
3. A central service (DDM) maintains the routing table
4. Dante Controller captures this info when flows are created and stores it locally
