# Dante Control Protocol Notes

All Dante control packets are UDP on port 4440.

## Packet Header (10 bytes)

```
0x00: u8   magic        # 0x27=standard, 0x28=extended
0x01: u8   seq_lo
0x02: u16  length       # total packet length
0x04: u16  seq_id
0x06: u16  command
0x08: u16  status
0x0a: ...  args/data
```

All multi-byte fields are big-endian.

## Commands

### 0x1000 - Channel Count Query

Response:
```
0x0c: u16  tx_count
0x0e: u16  rx_count
```

### 0x3000 - Subscription Query (Standard)

Works for multicast; may return empty for unicast.

Request args (6 bytes):
```
0x00: u16  0x0001
0x02: u16  page_num
0x04: u16  0x0000
```

Response record types (at 0x0e):
- `0x0006` = unicast
- `0x000e` = multicast

### 0x3400 - Subscription Query (Extended)

Uses magic=0x28. Works for unicast flows.

Request args (24 bytes):
```
0x07: u8   0x01
0x08: u16  page_type    # 0x0001=first, 0x0003=subsequent
0x0a: u16  start_ch     # 1, 17, 33, 49, ...
```

## 0x3400 Response

```
0x00: [10] header
0x0a: [8]  extended_header
0x12: [32] offset_table     # 16 × u16 record offsets
0x32: ...  records + strings
```

Status (at 0x08):
- `0x8112` = has subscription data
- `0x0001` = empty page

### Offset Table

16 entries at 0x12-0x31, each a u16 absolute offset to a record.
Zero offset = no more records.

### Subscription Record

Two record formats exist, distinguished by marker position.

#### Format 1: 0x141c records (numbered audio/video channels)

```
record+0x00: u16  0x141c          # record marker
record+0x02: u16  channel_num     # RX channel number
record+0x04: u16  0x0000
record+0x06: u16  0x0003
record+0x08: u16  channel_num     # repeated
record+0x0a: u16  0x0000
record+0x0c: u16  0x0000
record+0x0e: u16  channel_type    # 0x000f=audio, 0x000e=video
...
record+0x2c: u16  tx_ch_offset    # absolute offset to TX channel name string
record+0x2e: u16  tx_dev_offset   # absolute offset to TX device name string
record+0x31: u8   flow_status     # 0x00=unsubscribed, 0x01=no active source, 0x09=active
```

**Channel type (at record+0x0e):**
- `0x000f` = audio channel
- `0x000e` = video channel

**Flow status (at record+0x31):**
- `0x00` = unsubscribed
- `0x01` = subscribed but source not available (no active source)
- `0x09` = subscribed and receiving (active flow)

#### Format 2: 0x141a records (special channels: Video, Serial, USB)

```
record+0x00: u16  0x141a          # record marker
record+0x02: u16  channel_num     # e.g., 0x0009 = channel 9
record+0x04: u16  ??
record+0x06: u16  ??
...
record+0x2c: u16  tx_ch_offset    # same position as 0x141c
record+0x2e: u16  tx_dev_offset   # same position as 0x141c
```

These are video channels (Dante AV "Video" aggregate channel).

Both 0x141c and 0x141a records use the same offsets for tx_ch and tx_dev (+44 and +46).

**Subscription presence:**
- Both offsets non-zero = subscribed to a source
- Both offsets zero = unsubscribed

**Flow status (record+0x31):**
- `0x00` = unsubscribed (no subscription configured)
- `0x01` = subscribed but not receiving (source device offline or unavailable)
- `0x09` = subscribed and actively receiving audio/video

### String Table

Null-terminated strings referenced by absolute offset from packet start.
Multiple records share strings (e.g., same device name).

## Example: Page 2 Response (channels 17-32)

```
Offset table: 0050 0090 00d0 0110 0158 0194 01d8 021c 0258 ...

Record at 0x0050 (RX ch 17):
  0x0050+0x2c: 0032 0035
  String at 0x32: "01"       -> TX channel
  String at 0x35: "MICS-E"   -> TX device
  Result: MICS-E[01] -> ch17

Record at 0x0158 (RX ch 21):
  0x0158+0x2c: 0032 0148
  String at 0x32: "01"
  String at 0x148: "TX-QLAB-1"
  Result: TX-QLAB-1[01] -> ch21

Record at 0x01d8 (RX ch 23):
  0x01d8+0x2c: 01cc 01d1
  String at 0x1cc: "Left"
  String at 0x1d1: "BT"
  Result: BT[Left] -> ch23

Record at 0x0258 (RX ch 25):
  0x0258+0x2c: 0000 0000
  Result: UNSUBSCRIBED
```

## Parsing Algorithm

1. Check magic=0x28, command=0x3400, status=0x8112
2. Read 16 offsets from 0x12-0x31
3. For each non-zero offset, detect record format:
   - If offset+0x00 == 0x141c: Format 1 (numbered channel)
     - channel_type at offset+0x0e (0x000f=audio, 0x000e=video)
     - tx_ch_offset at offset+0x2c
     - tx_dev_offset at offset+0x2e
   - If offset+0x00 == 0x141a: Format 2 (special channel)
     - Assume video type
     - tx_ch_offset at offset+0x2c (same as 0x141c)
     - tx_dev_offset at offset+0x2e (same as 0x141c)
4. If tx_ch_offset and tx_dev_offset are both zero: skip (unsubscribed)
5. Read null-terminated strings at those offsets
6. RX channel = page_start + record_index

---

## Additional Commands

### 0x2000 - TX Channel Info

Request args (6 bytes):
```
0x00: u16  0x0001
0x02: u16  page_num
0x04: u16  0x0000
```

Response contains TX channel entries:
```
0x00: u16  channel_num
0x02: u16  channel_type    # see below
0x04: u16  name_offset
0x06: u16  unknown
```

Observed channel_type values:
- `0x0107` = audio channel (seen on MICS, SQ-7, speaker devices)
- `0x0007` = possibly video or different encoding?

Sample rate `0xbb80` (48000) appears in responses.

### 0x3600 - TX Flow Info

Uses magic=0x28. Returns info about outgoing flows.

Response includes IP addresses of flow destinations.

---

## Multicast Group Ranges

Audio and video use different multicast IP ranges:
- `239.69.x.x` - `239.71.x.x` = Dante audio multicast
- `239.253.x.x` = Dante AV (video) multicast

---

## Channel Type Detection

**SOLVED**: Audio vs video channels are distinguished by the channel_type field at record+0x0e in 0x3400 responses:
- `0x000f` = audio channel
- `0x000e` = video channel

Dante AV devices (TX-*, RX-* naming convention) have both audio and video channels. The type must be checked per-channel, not per-device.

---

## Open Questions

### Other Channel Types

Video devices have additional channel types with marker 0x141a instead of 0x141c:
- "Video" channels (the actual video stream)
- "Serial" channels
- "USB" channels

These use a different record structure. Need to decode the 0x141a record format.

### 0x2000 Channel Type Field

The 0x2000 response has a channel_type field at entry+0x02. Observed values:
- `0x0007` seen on Ultimo X (audio devices)
- Need to compare with video device 0x2000 responses
