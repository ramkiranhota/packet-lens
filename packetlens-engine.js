/**
 * packetlens-engine.js
 * ---------------------------------------------------------------
 * Pure, framework-agnostic pcap parsing and traffic-analysis logic.
 * Has zero DOM dependency: everything here operates on ArrayBuffer /
 * DataView and plain JS objects, so it runs unchanged in the browser
 * or under Node (e.g. for unit tests or a future CLI/backend reuse).
 *
 * Exposed API:
 *   PacketLensEngine.parsePcap(arrayBuffer)      -> Packet[]
 *   PacketLensEngine.parsePacket(dv, off, len, ts, idx) -> Packet
 *   PacketLensEngine.analyze(packets)            -> Analysis
 *   PacketLensEngine.tcpFlagsToStr(flagsByte)    -> string
 *   PacketLensEngine.ipToStr(dv, offset)         -> string
 *   PacketLensEngine.macToStr(dv, offset)        -> string
 * ---------------------------------------------------------------
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PacketLensEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------- Low-level field readers ----------
  function ipToStr(dv, off) {
    return `${dv.getUint8(off)}.${dv.getUint8(off + 1)}.${dv.getUint8(off + 2)}.${dv.getUint8(off + 3)}`;
  }

  function macToStr(dv, off) {
    const b = [];
    for (let i = 0; i < 6; i++) b.push(dv.getUint8(off + i).toString(16).padStart(2, '0'));
    return b.join(':');
  }

  function tcpFlagsToStr(flags) {
    if (flags == null) return '—';
    const names = [['FIN', 0x01], ['SYN', 0x02], ['RST', 0x04], ['PSH', 0x08], ['ACK', 0x10], ['URG', 0x20]];
    const set = names.filter(([, bit]) => flags & bit).map(([n]) => n);
    return set.length ? set.join(', ') : '—';
  }

  // ---------- Per-packet decoding (Ethernet II / IPv4 / TCP,UDP,ICMP) ----------
  function parsePacket(dv, off, len, ts, idx) {
    const base = {
      idx, ts, len, proto: 'other', src: null, dst: null, sport: null, dport: null,
      srcMac: null, dstMac: null, ttl: null, ipVersion: null, ihl: null,
      tcpFlags: null, icmpType: null, icmpCode: null,
      rawOff: off, rawLen: len, dv // kept for on-demand hex/field rendering, not for aggregation
    };
    if (len < 14) return base;
    base.dstMac = macToStr(dv, off);
    base.srcMac = macToStr(dv, off + 6);
    const ethertype = dv.getUint16(off + 12, false);
    if (ethertype !== 0x0800) return base; // only IPv4 handled
    const ipOff = off + 14;
    if (ipOff + 20 > off + len) return base;
    const verIhl = dv.getUint8(ipOff);
    base.ipVersion = verIhl >> 4;
    const ihl = (verIhl & 0x0f) * 4;
    base.ihl = ihl;
    base.ttl = dv.getUint8(ipOff + 8);
    const protoNum = dv.getUint8(ipOff + 9);
    const src = ipToStr(dv, ipOff + 12);
    const dst = ipToStr(dv, ipOff + 16);
    base.src = src; base.dst = dst;

    const l4Off = ipOff + ihl;
    if (protoNum === 6 && l4Off + 14 <= off + len) {
      base.proto = 'TCP';
      base.sport = dv.getUint16(l4Off, false);
      base.dport = dv.getUint16(l4Off + 2, false);
      base.tcpFlags = dv.getUint8(l4Off + 13);
    } else if (protoNum === 17 && l4Off + 4 <= off + len) {
      base.proto = 'UDP';
      base.sport = dv.getUint16(l4Off, false);
      base.dport = dv.getUint16(l4Off + 2, false);
    } else if (protoNum === 1 && l4Off + 2 <= off + len) {
      base.proto = 'ICMP';
      base.icmpType = dv.getUint8(l4Off);
      base.icmpCode = dv.getUint8(l4Off + 1);
    } else {
      base.proto = 'IP/' + protoNum;
    }
    return base;
  }

  // ---------- Format dispatcher ----------
  function parsePcap(buf) {
    if (buf.byteLength < 24) throw new Error('File too small to be a valid capture.');
    const dv = new DataView(buf);
    const magicLE = dv.getUint32(0, true);
    const magicBE = dv.getUint32(0, false);

    if (magicLE === 0xa1b2c3d4 || magicBE === 0xa1b2c3d4 || magicLE === 0xa1b23c4d || magicBE === 0xa1b23c4d) {
      return parseClassicPcap(buf, dv);
    }
    if (magicLE === 0x0a0d0d0a || magicBE === 0x0a0d0d0a) {
      return parsePcapng(buf, dv);
    }
    throw new Error('Unrecognized file — not a classic .pcap or .pcapng capture.');
  }

  // ---------- Classic libpcap: global header + linear packet records ----------
  function parseClassicPcap(buf, dv) {
    const magicLE = dv.getUint32(0, true);
    const magicBE = dv.getUint32(0, false);
    let little, nsec;
    if (magicLE === 0xa1b2c3d4) { little = true; nsec = false; }
    else if (magicBE === 0xa1b2c3d4) { little = false; nsec = false; }
    else if (magicLE === 0xa1b23c4d) { little = true; nsec = true; }
    else { little = false; nsec = true; }

    let offset = 24; // global header size
    const packets = [];
    let idx = 0;

    while (offset + 16 <= buf.byteLength) {
      const ts_sec = dv.getUint32(offset, little);
      const ts_frac = dv.getUint32(offset + 4, little);
      const incl_len = dv.getUint32(offset + 8, little);
      offset += 16;
      if (offset + incl_len > buf.byteLength) break;

      const ts = ts_sec + ts_frac / (nsec ? 1e9 : 1e6);
      packets.push(parsePacket(dv, offset, incl_len, ts, idx++));
      offset += incl_len;
    }
    return packets;
  }

  // ---------- pcapng: block-based container format ----------
  // Blocks: Section Header Block (0x0A0D0D0A), Interface Description Block
  // (0x00000001), Enhanced Packet Block (0x00000006), the older Packet Block
  // (0x00000002, deprecated) and Simple Packet Block (0x00000003). Anything
  // else (name resolution, interface stats, decryption secrets, custom
  // blocks) is skipped using its own length field — we don't need to
  // understand a block to skip past it.
  function parsePcapng(buf, dv) {
    let offset = 0;
    let little = true;           // re-detected at each Section Header Block
    let interfaces = [];         // per-section interface list: { tsresolDivisor }
    const packets = [];
    let idx = 0;

    function readOptions_ifTsresol(bodyStart, bodyEnd, little) {
      // Options are TLV: option code (2B) + option length (2B) + value
      // (padded to a 4-byte boundary), terminated by opt_endofopt (code 0).
      let o = bodyStart;
      let divisor = 1e6; // default resolution: microseconds, per the pcapng spec
      while (o + 4 <= bodyEnd) {
        const code = dv.getUint16(o, little);
        const len = dv.getUint16(o + 2, little);
        if (code === 0 && len === 0) break; // opt_endofopt
        if (code === 9 && len >= 1) {       // if_tsresol
          const b = dv.getUint8(o + 4);
          divisor = (b & 0x80) ? Math.pow(2, b & 0x7f) : Math.pow(10, b);
        }
        o += 4 + len + ((4 - (len % 4)) % 4); // advance past value + padding
      }
      return divisor;
    }

    while (offset + 12 <= buf.byteLength) {
      // Block Type is read the same way regardless of byte order for the
      // one block that matters here (0x0A0D0D0A is a byte-order palindrome),
      // so we can always detect a new Section Header Block correctly.
      const typeLE = dv.getUint32(offset, true);

      if (typeLE === 0x0a0d0d0a) {
        // Section Header Block — (re)establish endianness for this section
        // by locating the byte-order magic at a fixed offset within the body.
        const bomLE = dv.getUint32(offset + 8, true);
        const bomBE = dv.getUint32(offset + 8, false);
        if (bomLE === 0x1a2b3c4d) little = true;
        else if (bomBE === 0x1a2b3c4d) little = false;
        else throw new Error('Malformed pcapng section header (bad byte-order magic).');
        interfaces = []; // a new section restarts interface numbering
      }

      const blockType = dv.getUint32(offset, little);
      const blockLen = dv.getUint32(offset + 4, little);
      if (blockLen < 12 || offset + blockLen > buf.byteLength) break;
      const bodyStart = offset + 8;
      const bodyEnd = offset + blockLen - 4;

      if (blockType === 0x00000001) {
        // Interface Description Block: LinkType(2) Reserved(2) SnapLen(4) Options
        const tsresolDivisor = readOptions_ifTsresol(bodyStart + 8, bodyEnd, little);
        interfaces.push({ tsresolDivisor });
      } else if (blockType === 0x00000006) {
        // Enhanced Packet Block: IfaceID(4) TsHigh(4) TsLow(4) CapLen(4) OrigLen(4) Data...
        const ifaceId = dv.getUint32(bodyStart, little);
        const tsHigh = dv.getUint32(bodyStart + 4, little);
        const tsLow = dv.getUint32(bodyStart + 8, little);
        const capLen = dv.getUint32(bodyStart + 12, little);
        const divisor = (interfaces[ifaceId] && interfaces[ifaceId].tsresolDivisor) || 1e6;
        // Combine the two 32-bit halves as seconds directly (rather than
        // forming the full 64-bit integer first) to avoid precision loss —
        // nanosecond-resolution raw counters exceed Number.MAX_SAFE_INTEGER.
        const ts = tsHigh * (4294967296 / divisor) + tsLow / divisor;
        const frameStart = bodyStart + 20;
        if (frameStart + capLen <= bodyEnd + 4) {
          packets.push(parsePacket(dv, frameStart, capLen, ts, idx++));
        }
      } else if (blockType === 0x00000002) {
        // Packet Block (deprecated): IfaceID(2) Drops(2) TsHigh(4) TsLow(4) CapLen(4) OrigLen(4) Data...
        const ifaceId = dv.getUint16(bodyStart, little);
        const tsHigh = dv.getUint32(bodyStart + 4, little);
        const tsLow = dv.getUint32(bodyStart + 8, little);
        const capLen = dv.getUint32(bodyStart + 12, little);
        const divisor = (interfaces[ifaceId] && interfaces[ifaceId].tsresolDivisor) || 1e6;
        const ts = tsHigh * (4294967296 / divisor) + tsLow / divisor;
        const frameStart = bodyStart + 20;
        if (frameStart + capLen <= bodyEnd + 4) {
          packets.push(parsePacket(dv, frameStart, capLen, ts, idx++));
        }
      } else if (blockType === 0x00000003) {
        // Simple Packet Block: OrigLen(4) Data... — no timestamp or interface
        // recorded, so we synthesize a monotonically increasing one.
        const capLen = Math.min(dv.getUint32(bodyStart, little), bodyEnd - (bodyStart + 4));
        const frameStart = bodyStart + 4;
        packets.push(parsePacket(dv, frameStart, capLen, idx * 1e-6, idx));
        idx++;
      }
      // Any other block type (name resolution, interface stats, decryption
      // secrets, custom blocks, ...) is simply skipped.

      offset += blockLen;
    }
    return packets;
  }

  // ---------- Aggregation + anomaly heuristics ----------
  function analyze(packets) {
    const total = packets.length;
    const totalBytes = packets.reduce((s, p) => s + p.len, 0);
    const times = packets.map(p => p.ts);
    const minT = Math.min(...times), maxT = Math.max(...times);
    const duration = Math.max(maxT - minT, 0.001);

    const hosts = new Set();
    packets.forEach(p => { if (p.src) hosts.add(p.src); if (p.dst) hosts.add(p.dst); });

    // protocol distribution
    const protoCounts = {};
    packets.forEach(p => { protoCounts[p.proto] = (protoCounts[p.proto] || 0) + 1; });

    // bandwidth over time, bucketed into ~40 buckets
    const bucketCount = 40;
    const bucketDur = duration / bucketCount;
    const buckets = new Array(bucketCount).fill(0);
    packets.forEach(p => {
      let idx = Math.floor((p.ts - minT) / bucketDur);
      if (idx >= bucketCount) idx = bucketCount - 1;
      if (idx < 0) idx = 0;
      buckets[idx] += p.len;
    });

    // top talkers by bytes (src+dst pair)
    const talkerBytes = {};
    packets.forEach(p => {
      if (!p.src || !p.dst) return;
      const key = p.src + ' → ' + p.dst;
      talkerBytes[key] = (talkerBytes[key] || 0) + p.len;
    });
    const topTalkers = Object.entries(talkerBytes).sort((a, b) => b[1] - a[1]).slice(0, 8);

    // top ports
    const portCounts = {};
    packets.forEach(p => {
      if (p.dport != null) portCounts[p.dport] = (portCounts[p.dport] || 0) + 1;
    });
    const topPorts = Object.entries(portCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);

    // packet size histogram
    const sizeBins = [64, 128, 256, 512, 1024, 1500, Infinity];
    const sizeLabels = ['<64', '64-128', '128-256', '256-512', '512-1024', '1024-1500', '1500+'];
    const sizeHist = new Array(sizeBins.length).fill(0);
    packets.forEach(p => {
      for (let i = 0; i < sizeBins.length; i++) {
        if (p.len <= sizeBins[i]) { sizeHist[i]++; break; }
      }
    });

    // --- anomaly detection ---
    const alerts = [];
    // heavy talker: any single src IP responsible for >30% of total bytes
    const srcBytes = {};
    packets.forEach(p => { if (p.src) srcBytes[p.src] = (srcBytes[p.src] || 0) + p.len; });
    Object.entries(srcBytes).forEach(([ip, bytes]) => {
      const pct = bytes / totalBytes;
      if (pct > 0.3) {
        alerts.push({
          level: 'warn',
          title: `Heavy talker: ${ip}`,
          detail: `${(pct * 100).toFixed(1)}% of total traffic (${(bytes / 1024).toFixed(1)} KB)`
        });
      }
    });

    // possible port scan: (src,dst) pair touching many distinct dst ports
    const pairPorts = {};
    packets.forEach(p => {
      if (p.proto !== 'TCP' || !p.src || !p.dst) return;
      const key = p.src + '→' + p.dst;
      if (!pairPorts[key]) pairPorts[key] = new Set();
      pairPorts[key].add(p.dport);
    });
    Object.entries(pairPorts).forEach(([key, ports]) => {
      if (ports.size >= 15) {
        alerts.push({
          level: 'crit',
          title: `Possible port scan: ${key}`,
          detail: `${ports.size} distinct destination ports contacted`
        });
      }
    });

    // bandwidth spike: any bucket > 8x median
    const sortedBuckets = [...buckets].filter(b => b > 0).sort((a, b) => a - b);
    const median = sortedBuckets.length ? sortedBuckets[Math.floor(sortedBuckets.length / 2)] : 0;
    buckets.forEach((b, i) => {
      if (median > 0 && b > median * 8) {
        alerts.push({
          level: 'warn',
          title: `Traffic spike near t+${(i * bucketDur).toFixed(1)}s`,
          detail: `${(b / 1024).toFixed(1)} KB in bucket vs ${(median / 1024).toFixed(1)} KB median`
        });
      }
    });

    return {
      total, totalBytes, duration, hosts, protoCounts, buckets, bucketDur,
      topTalkers, topPorts, sizeHist, sizeLabels, alerts, packets, minT
    };
  }

  return { parsePcap, parseClassicPcap, parsePcapng, parsePacket, analyze, tcpFlagsToStr, ipToStr, macToStr };
});
