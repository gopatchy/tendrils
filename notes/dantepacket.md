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

Each record is 56+ bytes. The offset table points to record start.

```
record+0x00: [40] record_header
record+0x28: u16  0x0608          # marker
record+0x2a: u16  0x0000
record+0x2c: u16  tx_ch_offset    # absolute offset to TX channel name string
record+0x2e: u16  tx_dev_offset   # absolute offset to TX device name string
record+0x30: [4]  flags
record+0x34: u32  0x02020000      # string marker
record+0x38: ...  inline_strings  # (unreliable, use offsets above)
```

**Subscription status:**
- Both offsets non-zero = subscribed
- Both offsets zero = unsubscribed

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
3. For each non-zero offset:
   - Read u16 at offset+0x2c (tx_ch_offset)
   - Read u16 at offset+0x2e (tx_dev_offset)
   - If both zero: skip (unsubscribed)
   - Else: read null-terminated strings at those offsets
   - RX channel = page_start + record_index
