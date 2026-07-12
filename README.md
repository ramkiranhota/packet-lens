# PacketLens

A zero-install, client-side dashboard for interactive pcap traffic analysis.
Everything runs in the browser — no server, no upload, no dependency beyond
Chart.js (loaded from cdnjs).

## Files
- `index.html` — markup + styling, loads Chart.js then the two scripts below
- `packetlens-engine.js` — pure parsing/analysis "backend". Zero DOM
  dependency: binary pcap parsing, protocol decoding, aggregation, and
  anomaly heuristics. Works as `window.PacketLensEngine` in the browser or
  as a plain CommonJS module in Node (`require('./packetlens-engine.js')`),
  which makes it independently unit-testable.
- `packetlens-ui.js` — the view layer: DOM rendering, Chart.js wiring, the
  packet-details table, file-upload handling, the dark/light theme toggle,
  and the main tab switcher. Depends on `packetlens-engine.js` and Chart.js.
- `sample_traffic.pcap` — synthetic capture (web/DNS/ICMP traffic plus a
  planted heavy talker and port scan) for testing.

## Running locally
Open `index.html` in any modern browser and load a `.pcap` file.

## Features
- **Tabbed layout**: "Packet Details" is the default/main tab (the searchable,
  paginated per-packet table with hex/field inspector); "Traffic Overview"
  holds the aggregate views — bandwidth over time, protocol distribution,
  top talkers, top ports, packet-size histogram, and anomalies.
- Anomaly detection: heavy talkers, possible port scans, bandwidth spikes
- Dark/light theme toggle, persisted via localStorage, respecting the OS's
  `prefers-color-scheme` on first visit. Charts, the trace sparkline, and
  all panels re-theme live, including across tab switches.

## Notes
- Supports classic .pcap (libpcap) format only — not .pcapng.
- IPv4 / Ethernet II only.
