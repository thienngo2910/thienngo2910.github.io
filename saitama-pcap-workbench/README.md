# Saitama PCAP Workbench

Browser based PCAP and PCAPNG triage for the Saitama network forensics exercise.

## Use

Open `index.html` in a modern browser and choose a `.pcap` or `.pcapng` file. The capture is parsed locally in the browser; the page does not upload it or send it to an analysis API. Use the tabs to review packets, TCP/UDP conversations, DNS queries, heuristic findings, and the generated report. Export packet CSV or the complete analysis JSON from the overview.

## Deployment

This static page is published at:

`https://thienngo2910.github.io/saitama-pcap-workbench/`

The source lives in the `saitama-pcap-workbench/` directory of the existing `thienngo2910.github.io` GitHub Pages repository. The rest of that site is left untouched.

## Current analysis coverage

- Classic PCAP in little/big endian and microsecond/nanosecond timestamp formats.
- PCAPNG section, interface and enhanced packet blocks; Ethernet, Linux cooked v1/v2, raw IPv4.
- Ethernet VLAN tags, IPv4/IPv6, ARP, TCP, UDP, ICMP/ICMPv6 packet summaries.
- DNS question names/types, endpoint and protocol counts, bidirectional TCP/UDP conversation grouping.
- Heuristic flags for cleartext services and visible credential-like strings, plus unusually long DNS names.
- Packet table filtering, CSV packet export, JSON findings export, and a text report.

Heuristic results are triage indicators, not proof of malicious activity. Validate findings against the original capture and the network context. The current parser does not reassemble TCP streams or decode TLS-encrypted application data.

