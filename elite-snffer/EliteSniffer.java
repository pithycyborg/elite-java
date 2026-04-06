#!/usr/bin/env -S java --source 21

/**
 * EliteSniffer — Single-file Java PCAP analyzer
 * Zero dependencies. Streaming decode. VLAN + IPv6 extensions + TLS hints + JA3 fingerprinting.
 * Built for people who like their tools sharp and self-contained.
 * 100% free for you to use.
 * Join the author's AI newsletter: PithyCyborg.com
 */

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class EliteSniffer {

    static final String RESET   = "\u001B[0m";
    static final String BOLD    = "\u001B[1m";
    static final String DIM     = "\u001B[2m";
    static final String CYAN    = "\u001B[36m";
    static final String RED     = "\u001B[31m";
    static final String GREEN   = "\u001B[32m";
    static final String YELLOW  = "\u001B[33m";
    static final String BLUE    = "\u001B[34m";
    static final String MAGENTA = "\u001B[35m";
    static final String GRAY    = "\u001B[90m";

    public static void main(String[] args) {
        try {
            if (args.length == 0 || has(args, "--help") || has(args, "-h")) { usage(); return; }
            banner();
            Config cfg = Config.parse(args);
            switch (cfg.mode) {
                case SUMMARY -> analyzeFile(cfg);
                case EXPORT  -> exportFiltered(cfg);
                case LIVE    -> liveCapture(cfg);
            }
        } catch (Exception e) {
            System.err.println(RED + "Error: " + e.getMessage() + RESET);
            if (has(args, "--debug")) e.printStackTrace(System.err);
        }
    }

    static void banner() {
        System.out.println(CYAN + BOLD + "╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    ELITE SNIFFER // v2.5                    ║");
        System.out.println("║     single-file java network forensics and pcap slicer     ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝" + RESET);
    }

    static void usage() {
        banner();
        System.out.println("Usage:");
        System.out.println("  java EliteSniffer.java <capture.pcap> [--limit N] [--filter expr] [--dump] [--json]");
        System.out.println("  java EliteSniffer.java --export <in.pcap> <out.pcap> [--filter expr]");
        System.out.println("  java EliteSniffer.java --live <iface> [--count N] [--filter expr] [--dump]");
        System.out.println();
        System.out.println("Filter examples: tcp | udp and port 53 | src host 8.8.8.8 | tcp and port 443");
    }

    // ─────────────────────────── MODES ───────────────────────────

    static void analyzeFile(Config cfg) throws Exception {
        try (PcapStream stream = new PcapStream(Files.newInputStream(Paths.get(cfg.input)))) {
            PacketFilter filter = PacketFilter.parse(cfg.filterExpr);
            Summary summary = new Summary();
            int shown = 0;

            System.out.println("Scanning  : " + cfg.input);
            System.out.println("Linktype  : " + linktypeName(stream.header.network));
            System.out.println("Precision : " + (stream.header.nanoPrecision ? "nanoseconds" : "microseconds"));
            System.out.println("─".repeat(112));

            while (stream.hasNext()) {
                PacketRecord rec = stream.next();
                DecodedPacket p = Decoder.decode(rec, stream.header);
                if (!filter.matches(p)) continue;
                summary.accept(p);
                if (shown < cfg.limit) {
                    printPacketRow(++shown, p);
                    if (cfg.dump) printVerbose(p);
                }
            }

            printSummary(summary, stream.header, cfg.filterExpr);
            if (cfg.json) printJson(summary, cfg.filterExpr, stream.header.network);
        }
    }

    static void exportFiltered(Config cfg) throws Exception {
        try (PcapStream stream = new PcapStream(Files.newInputStream(Paths.get(cfg.input)));
             OutputStream out = new BufferedOutputStream(Files.newOutputStream(Paths.get(cfg.output)))) {
            PacketFilter filter = PacketFilter.parse(cfg.filterExpr);
            PcapWriter.writeGlobalHeader(out, stream.header);
            long kept = 0;
            while (stream.hasNext()) {
                PacketRecord rec = stream.next();
                DecodedPacket p = Decoder.decode(rec, stream.header);
                if (filter.matches(p)) {
                    PcapWriter.writeRecord(out, rec, stream.header);
                    kept++;
                }
            }
            out.flush();
            System.out.println(GREEN + "Exported " + kept + " packets → " + cfg.output + RESET);
        }
    }

    static void liveCapture(Config cfg) throws Exception {
        List<String> cmd = List.of("tcpdump", "-i", cfg.iface, "-nn", "-U", "-w", "-", "-c", String.valueOf(cfg.count));
        Process proc = new ProcessBuilder(cmd).redirectError(ProcessBuilder.Redirect.INHERIT).start();
        try (PcapStream stream = new PcapStream(proc.getInputStream())) {
            PacketFilter filter = PacketFilter.parse(cfg.filterExpr);
            Summary summary = new Summary();
            int shown = 0;
            while (stream.hasNext()) {
                PacketRecord rec = stream.next();
                DecodedPacket p = Decoder.decode(rec, stream.header);
                if (!filter.matches(p)) continue;
                summary.accept(p);
                printPacketRow(++shown, p);
                if (cfg.dump) printVerbose(p);
            }
            printSummary(summary, stream.header, cfg.filterExpr);
        } finally {
            proc.destroy();
            proc.waitFor(5, TimeUnit.SECONDS);
        }
    }

    // ─────────────────────────── CONFIG ───────────────────────────

    enum Mode { SUMMARY, EXPORT, LIVE }

    static class Config {
        Mode   mode       = Mode.SUMMARY;
        String input      = null;
        String output     = null;
        String iface      = null;
        String filterExpr = null;
        int    limit      = Integer.MAX_VALUE;
        int    count      = 100;
        boolean dump      = false;
        boolean json      = false;

        static Config parse(String[] args) {
            Config c = new Config();
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--export" -> { c.mode = Mode.EXPORT;  c.input  = args[++i]; c.output = args[++i]; }
                    case "--live"   -> { c.mode = Mode.LIVE;    c.iface  = args[++i]; }
                    case "--limit"  -> c.limit      = Integer.parseInt(args[++i]);
                    case "--count"  -> c.count      = Integer.parseInt(args[++i]);
                    case "--filter" -> c.filterExpr = args[++i];
                    case "--dump"   -> c.dump       = true;
                    case "--json"   -> c.json       = true;
                    default -> { if (c.input == null && !args[i].startsWith("--")) c.input = args[i]; }
                }
            }
            if (c.mode == Mode.SUMMARY && c.input == null)
                throw new IllegalArgumentException("No input file specified");
            return c;
        }
    }

    // ─────────────────────────── PCAP I/O ───────────────────────────

    static class PcapHeader {
        int magicRaw;
        boolean bigEndian;
        boolean nanoPrecision;
        int major, minor;
        long snaplen;
        long network;
    }

    static record PacketRecord(long tsSec, long tsFrac, long origLen, byte[] data) {}

    static class PcapStream implements AutoCloseable {
        private final DataInputStream in;
        final PcapHeader header;
        private PacketRecord pending;
        private boolean eof;

        PcapStream(InputStream raw) throws IOException {
            this.in = new DataInputStream(new BufferedInputStream(raw));
            this.header = readGlobalHeader();
            advance();
        }

        private PcapHeader readGlobalHeader() throws IOException {
            byte[] gh = in.readNBytes(24);
            if (gh.length < 24) throw new EOFException("PCAP global header too short");
            int magic = u32be(gh, 0);
            PcapHeader h = new PcapHeader();
            h.magicRaw = magic;
            switch (magic) {
                case 0xa1b2c3d4 -> { h.bigEndian = true;  h.nanoPrecision = false; }
                case 0xd4c3b2a1 -> { h.bigEndian = false; h.nanoPrecision = false; }
                case 0xa1b23c4d -> { h.bigEndian = true;  h.nanoPrecision = true;  }
                case 0x4d3cb2a1 -> { h.bigEndian = false; h.nanoPrecision = true;  }
                default -> throw new IOException("Unknown PCAP magic: 0x" + Integer.toHexString(magic));
            }
            h.major   = u16(gh, 4, h.bigEndian);
            h.minor   = u16(gh, 6, h.bigEndian);
            h.snaplen = u32(gh, 16, h.bigEndian);
            h.network = u32(gh, 20, h.bigEndian) & 0xFFFFFFFFL;
            return h;
        }

        private void advance() throws IOException {
            if (eof) { pending = null; return; }
            byte[] ph = in.readNBytes(16);
            if (ph.length == 0) { eof = true; pending = null; return; }
            if (ph.length < 16) throw new EOFException("Truncated per-packet header");
            long tsSec  = u32(ph, 0, header.bigEndian);
            long tsFrac = u32(ph, 4, header.bigEndian);
            long incl   = u32(ph, 8, header.bigEndian);
            long orig   = u32(ph, 12, header.bigEndian);
            if (incl < 0 || incl > 256_000_000L) throw new IOException("Suspicious incl_len: " + incl);
            byte[] data = in.readNBytes((int) incl);
            if (data.length < incl) throw new EOFException("Truncated packet body");
            pending = new PacketRecord(tsSec, tsFrac, orig, data);
        }

        boolean hasNext() { return pending != null; }
        PacketRecord next() throws IOException {
            if (pending == null) throw new NoSuchElementException();
            PacketRecord cur = pending;
            advance();
            return cur;
        }
        public void close() throws IOException { in.close(); }
    }

    static class PcapWriter {
        static void writeGlobalHeader(OutputStream os, PcapHeader h) throws IOException {
            w32(os, h.magicRaw, false);
            w16(os, h.major, h.bigEndian);
            w16(os, h.minor, h.bigEndian);
            w32(os, 0, h.bigEndian);
            w32(os, 0, h.bigEndian);
            w32(os, h.snaplen, h.bigEndian);
            w32(os, h.network, h.bigEndian);
        }
        static void writeRecord(OutputStream os, PacketRecord r, PcapHeader h) throws IOException {
            w32(os, r.tsSec, h.bigEndian);
            w32(os, r.tsFrac, h.bigEndian);
            w32(os, r.data.length, h.bigEndian);
            w32(os, r.origLen, h.bigEndian);
            os.write(r.data);
        }
    }

    // ─────────────────────────── DECODING ───────────────────────────

    static class DecodedPacket {
        Instant timestamp;
        String protocol = "UNKNOWN";
        String src = "-", dst = "-";
        int srcPort = -1, dstPort = -1;
        int ttl = -1;
        int length;
        long originalLength;
        String etherType = "-";
        String flags = "-";
        List<Integer> vlanTags = List.of();
        final List<String> notes = new ArrayList<>();

        String srcEndpoint() { return srcPort >= 0 ? src + ":" + srcPort : src; }
        String dstEndpoint() { return dstPort >= 0 ? dst + ":" + dstPort : dst; }
    }

    static class Decoder {

        static DecodedPacket decode(PacketRecord r, PcapHeader h) {
            DecodedPacket p = new DecodedPacket();
            long nanos = h.nanoPrecision ? r.tsFrac : r.tsFrac * 1_000_000L;
            p.timestamp = Instant.ofEpochSecond(r.tsSec, nanos);
            p.length = r.data.length;
            p.originalLength = r.origLen;

            switch ((int) h.network) {
                case 1   -> parseEthernet(r.data, 0, p);
                case 0   -> parseNullLoopback(r.data, 0, p);
                case 113 -> parseLinuxCooked(r.data, 0, p);
                default  -> { p.protocol = "LINKTYPE-" + h.network; p.notes.add("unsupported linktype"); }
            }
            return p;
        }

        static void parseEthernet(byte[] b, int off, DecodedPacket p) {
            if (b.length < off + 14) { p.protocol = "ETH(short)"; p.notes.add("short ethernet"); return; }
            int etherType = u16be(b, off + 12);
            int cur = off + 14;

            List<Integer> vlans = null;
            while (etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100) {
                if (b.length < cur + 4) { p.notes.add("truncated vlan tag"); return; }
                if (vlans == null) vlans = new ArrayList<>();
                vlans.add(u16be(b, cur) & 0x0FFF);
                etherType = u16be(b, cur + 2);
                cur += 4;
            }
            if (vlans != null) p.vlanTags = vlans;
            p.etherType = String.format("0x%04x", etherType);

            if      (etherType == 0x0800) parseIPv4(b, cur, p);
            else if (etherType == 0x86DD) parseIPv6(b, cur, p);
            else    p.protocol = "ETHER-" + String.format("%04x", etherType);
        }

        static void parseNullLoopback(byte[] b, int off, DecodedPacket p) {
            if (b.length < off + 4) { p.protocol = "NULL(short)"; return; }
            long af = u32(b, off, false);
            if      (af == 2) parseIPv4(b, off + 4, p);
            else if (af == 24 || af == 28 || af == 30) parseIPv6(b, off + 4, p);
            else p.protocol = "NULL-AF-" + af;
        }

        static void parseLinuxCooked(byte[] b, int off, DecodedPacket p) {
            if (b.length < off + 16) { p.protocol = "SLL(short)"; return; }
            int etherType = u16be(b, off + 14);
            int payload = off + 16;
            p.etherType = String.format("0x%04x", etherType);
            if      (etherType == 0x0800) parseIPv4(b, payload, p);
            else if (etherType == 0x86DD) parseIPv6(b, payload, p);
            else p.protocol = "SLL-" + String.format("%04x", etherType);
        }

        static void parseIPv4(byte[] b, int off, DecodedPacket p) {
            if (b.length < off + 20) { p.protocol = "IPv4(short)"; p.notes.add("truncated ipv4"); return; }
            int ver = (b[off] >> 4) & 0xF;
            int ihl = (b[off] & 0xF) * 4;
            if (ver != 4 || ihl < 20 || b.length < off + ihl) { p.protocol = "IPv4(bad)"; p.notes.add("malformed ipv4"); return; }
            p.ttl = b[off + 8] & 0xFF;
            int proto = b[off + 9] & 0xFF;
            int flagsFrag = u16be(b, off + 6);
            if ((flagsFrag & 0x3FFF) != 0) p.notes.add("fragmented ipv4");
            p.src = ipv4(b, off + 12);
            p.dst = ipv4(b, off + 16);
            parseTransport(b, off + ihl, proto, p);
        }

        static void parseIPv6(byte[] b, int off, DecodedPacket p) {
            if (b.length < off + 40) { p.protocol = "IPv6(short)"; p.notes.add("truncated ipv6"); return; }
            p.ttl = b[off + 7] & 0xFF;
            p.src = ipv6(b, off + 8);
            p.dst = ipv6(b, off + 24);
            int nextHeader = b[off + 6] & 0xFF;
            int cur = off + 40;
            while (nextHeader == 0 || nextHeader == 43 || nextHeader == 60 || nextHeader == 44) {
                if (b.length < cur + 8) break;
                nextHeader = b[cur] & 0xFF;
                cur += (nextHeader == 44) ? 8 : ((b[cur + 1] & 0xFF) + 1) * 8;
            }
            parseTransport(b, cur, nextHeader, p);
        }

        static void parseTransport(byte[] b, int off, int proto, DecodedPacket p) {
            switch (proto) {
                case 6  -> parseTcp(b, off, p);
                case 17 -> parseUdp(b, off, p);
                case 1  -> p.protocol = "ICMP";
                case 58 -> p.protocol = "ICMPv6";
                default -> p.protocol = "IP-" + proto;
            }
        }

        static void parseTcp(byte[] b, int off, DecodedPacket p) {
            p.protocol = "TCP";
            if (b.length < off + 20) return;
            p.srcPort = u16be(b, off);
            p.dstPort = u16be(b, off + 2);
            int dataOff = ((b[off + 12] >> 4) & 0xF) * 4;
            int flags = b[off + 13] & 0xFF;
            p.flags = tcpFlags(flags);
            int payload = off + Math.max(20, dataOff);
            if (payload < b.length) {
                if (p.srcPort == 80 || p.dstPort == 80 || p.srcPort == 8080 || p.dstPort == 8080)
                    sniffHttp(b, payload, p);
                if (p.srcPort == 443 || p.dstPort == 443)
                    sniffTls(b, payload, p);
            }
        }

        static void parseUdp(byte[] b, int off, DecodedPacket p) {
            p.protocol = "UDP";
            if (b.length < off + 8) return;
            p.srcPort = u16be(b, off);
            p.dstPort = u16be(b, off + 2);
            int payload = off + 8;
            if (payload < b.length && (p.srcPort == 53 || p.dstPort == 53)) sniffDns(b, payload, p);
        }

        static void sniffDns(byte[] b, int off, DecodedPacket p) {
            if (b.length < off + 12) return;
            int qd = u16be(b, off + 4);
            int an = u16be(b, off + 6);
            p.notes.add("dns qd=" + qd + " an=" + an);
        }

        static void sniffHttp(byte[] b, int off, DecodedPacket p) {
            int len = Math.min(96, b.length - off);
            if (len <= 0) return;
            String s = new String(b, off, len, StandardCharsets.ISO_8859_1);
            for (String verb : new String[]{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "HTTP/"}) {
                if (s.startsWith(verb)) {
                    p.notes.add("http " + s.split("\\r?\\n", 2)[0]);
                    return;
                }
            }
        }

        // ─── TLS + JA3 ───────────────────────────────────────────────

        static void sniffTls(byte[] b, int off, DecodedPacket p) {
            if (b.length < off + 5) return;
            int ct    = b[off] & 0xFF;
            int major = b[off + 1] & 0xFF;
            if (ct != 22 || major != 3) return;

            p.notes.add("tls handshake");

            // Need record layer (5 bytes) + handshake header (4 bytes)
            if (b.length < off + 9) return;
            int hsType = b[off + 5] & 0xFF;
            if (hsType != 1) return;  // ClientHello only

            // Handshake length (3-byte big-endian)
            int hsLen = ((b[off + 6] & 0xFF) << 16) | ((b[off + 7] & 0xFF) << 8) | (b[off + 8] & 0xFF);
            int base  = off + 9;      // start of ClientHello body
            int end   = base + hsLen;
            if (end > b.length) return;

            if (base + 2 > end) return;
            int chMajor = b[base] & 0xFF;
            int chMinor = b[base + 1] & 0xFF;
            int sslVersion = (chMajor << 8) | chMinor;
            int pos = base + 2 + 32;  // skip version(2) + random(32)

            // Session ID
            if (pos + 1 > end) return;
            int sessionLen = b[pos] & 0xFF;
            pos += 1 + sessionLen;

            // Cipher suites
            if (pos + 2 > end) return;
            int cipherLen = u16be(b, pos);
            pos += 2;
            List<Integer> ciphers = new ArrayList<>();
            for (int i = 0; i < cipherLen; i += 2) {
                if (pos + 2 > end) break;
                int c = u16be(b, pos);
                pos += 2;
                if (!isGrease(c)) ciphers.add(c);
            }

            // Compression methods
            if (pos + 1 > end) return;
            int compLen = b[pos] & 0xFF;
            pos += 1 + compLen;

            // Extensions
            List<Integer> extTypes  = new ArrayList<>();
            List<Integer> curves    = new ArrayList<>();
            List<Integer> pointFmts = new ArrayList<>();

            if (pos + 2 <= end) {
                int extTotalLen = u16be(b, pos);
                pos += 2;
                int extEnd = pos + extTotalLen;
                while (pos + 4 <= extEnd && pos + 4 <= end) {
                    int extType = u16be(b, pos);
                    int extLen  = u16be(b, pos + 2);
                    pos += 4;
                    int extDataEnd = pos + extLen;
                    if (!isGrease(extType)) {
                        extTypes.add(extType);
                        // Extension 10: supported_groups (elliptic curves)
                        if (extType == 10 && pos + 2 <= extDataEnd) {
                            int listLen = u16be(b, pos);
                            int gpos = pos + 2;
                            while (gpos + 2 <= pos + 2 + listLen && gpos + 2 <= extDataEnd) {
                                int g = u16be(b, gpos);
                                if (!isGrease(g)) curves.add(g);
                                gpos += 2;
                            }
                        // Extension 11: ec_point_formats
                        } else if (extType == 11 && pos + 1 <= extDataEnd) {
                            int listLen = b[pos] & 0xFF;
                            for (int i = 0; i < listLen && pos + 1 + i < extDataEnd; i++)
                                pointFmts.add(b[pos + 1 + i] & 0xFF);
                        }
                    }
                    pos = extDataEnd;
                }
            }

            // Build JA3 string: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
            String ja3String = sslVersion
                + "," + joinInts(ciphers)
                + "," + joinInts(extTypes)
                + "," + joinInts(curves)
                + "," + joinInts(pointFmts);

            p.notes.add("ja3=" + md5hex(ja3String.getBytes(StandardCharsets.UTF_8)));
            p.notes.add("ja3_raw=" + ja3String);
        }

        /** RFC 8701 GREASE values: 0x?A?A where both bytes are equal and low nibble is 0xA */
        static boolean isGrease(int v) {
            return (v & 0x0F0F) == 0x0A0A && ((v >> 8) & 0xFF) == (v & 0xFF);
        }

        static String joinInts(List<Integer> list) {
            if (list.isEmpty()) return "";
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append('-');
                sb.append(list.get(i));
            }
            return sb.toString();
        }

        static String tcpFlags(int f) {
            StringBuilder sb = new StringBuilder();
            if ((f & 0x02) != 0) sb.append("SYN,");
            if ((f & 0x10) != 0) sb.append("ACK,");
            if ((f & 0x01) != 0) sb.append("FIN,");
            if ((f & 0x04) != 0) sb.append("RST,");
            if ((f & 0x08) != 0) sb.append("PSH,");
            if ((f & 0x20) != 0) sb.append("URG,");
            return sb.isEmpty() ? "-" : sb.substring(0, sb.length() - 1);
        }
    }

    // ─────────────────────────── SUMMARY ───────────────────────────

    static class Summary {
        long total = 0, bytes = 0;
        Map<String, Long> protoCounts   = new LinkedHashMap<>();
        Map<String, Long> srcCounts     = new LinkedHashMap<>();
        Map<String, Long> dstCounts     = new LinkedHashMap<>();
        Map<String, Long> ja3Counts     = new LinkedHashMap<>();
        Instant firstSeen = null, lastSeen = null;

        void accept(DecodedPacket p) {
            total++;
            bytes += p.length;
            protoCounts.merge(p.protocol, 1L, Long::sum);
            srcCounts.merge(p.srcEndpoint(), 1L, Long::sum);
            dstCounts.merge(p.dstEndpoint(), 1L, Long::sum);
            if (firstSeen == null || p.timestamp.isBefore(firstSeen)) firstSeen = p.timestamp;
            if (lastSeen  == null || p.timestamp.isAfter(lastSeen))   lastSeen  = p.timestamp;
            // Track JA3 hashes
            for (String note : p.notes) {
                if (note.startsWith("ja3=")) {
                    ja3Counts.merge(note.substring(4), 1L, Long::sum);
                }
            }
        }
    }

    // ─────────────────────────── FILTER ───────────────────────────

    static class PacketFilter {
        enum Op { NONE, TCP, UDP, ICMP, PORT, SRC_HOST, DST_HOST, HOST, AND, OR }
        Op op;
        int port;
        String host;
        PacketFilter left, right;

        static PacketFilter parse(String expr) {
            if (expr == null || expr.isBlank()) { PacketFilter f = new PacketFilter(); f.op = Op.NONE; return f; }
            expr = expr.trim();
            // OR has lowest precedence
            int orIdx = indexOfKeyword(expr, " or ");
            if (orIdx >= 0) {
                PacketFilter f = new PacketFilter(); f.op = Op.OR;
                f.left  = parse(expr.substring(0, orIdx).trim());
                f.right = parse(expr.substring(orIdx + 4).trim());
                return f;
            }
            int andIdx = indexOfKeyword(expr, " and ");
            if (andIdx >= 0) {
                PacketFilter f = new PacketFilter(); f.op = Op.AND;
                f.left  = parse(expr.substring(0, andIdx).trim());
                f.right = parse(expr.substring(andIdx + 5).trim());
                return f;
            }
            PacketFilter f = new PacketFilter();
            if      (expr.equals("tcp"))            { f.op = Op.TCP; }
            else if (expr.equals("udp"))            { f.op = Op.UDP; }
            else if (expr.equals("icmp"))           { f.op = Op.ICMP; }
            else if (expr.startsWith("port "))      { f.op = Op.PORT;     f.port = Integer.parseInt(expr.substring(5).trim()); }
            else if (expr.startsWith("src host "))  { f.op = Op.SRC_HOST; f.host = expr.substring(9).trim(); }
            else if (expr.startsWith("dst host "))  { f.op = Op.DST_HOST; f.host = expr.substring(9).trim(); }
            else if (expr.startsWith("host "))      { f.op = Op.HOST;     f.host = expr.substring(5).trim(); }
            else                                    { f.op = Op.NONE; }
            return f;
        }

        static int indexOfKeyword(String s, String kw) {
            int i = s.indexOf(kw);
            return i;
        }

        boolean matches(DecodedPacket p) {
            return switch (op) {
                case NONE     -> true;
                case TCP      -> p.protocol.equals("TCP");
                case UDP      -> p.protocol.equals("UDP");
                case ICMP     -> p.protocol.equals("ICMP") || p.protocol.equals("ICMPv6");
                case PORT     -> p.srcPort == port || p.dstPort == port;
                case SRC_HOST -> p.src.equals(host);
                case DST_HOST -> p.dst.equals(host);
                case HOST     -> p.src.equals(host) || p.dst.equals(host);
                case AND      -> left.matches(p) && right.matches(p);
                case OR       -> left.matches(p) || right.matches(p);
            };
        }
    }

    // ─────────────────────────── OUTPUT ───────────────────────────

    static void printPacketRow(int n, DecodedPacket p) {
        String ts = p.timestamp != null ? p.timestamp.toString() : "-";
        String proto = padRight(p.protocol, 8);
        String src   = padRight(p.srcEndpoint(), 28);
        String dst   = padRight(p.dstEndpoint(), 28);
        String len   = String.valueOf(p.length);
        String notes = p.notes.isEmpty() ? "" : GRAY + " [" + String.join(", ", p.notes) + "]" + RESET;

        String protoColor = switch (p.protocol) {
            case "TCP"   -> CYAN;
            case "UDP"   -> GREEN;
            case "ICMP", "ICMPv6" -> YELLOW;
            default      -> BLUE;
        };

        System.out.printf("%s%5d%s  %s  %s%s%s  →  %s%s%s  %s%s%s%s%n",
            GRAY, n, RESET,
            ts,
            protoColor, proto, RESET,
            MAGENTA, src, RESET,
            CYAN, dst, RESET,
            notes);
    }

    static void printVerbose(DecodedPacket p) {
        System.out.println(DIM + "       TTL=" + p.ttl
            + "  ethertype=" + p.etherType
            + "  flags=" + p.flags
            + "  orig=" + p.originalLength
            + (p.vlanTags.isEmpty() ? "" : "  vlan=" + p.vlanTags)
            + RESET);
    }

    static void printSummary(Summary s, PcapHeader h, String filter) {
        System.out.println("─".repeat(112));
        System.out.println(BOLD + "Summary" + RESET);
        System.out.println("  Packets  : " + s.total);
        System.out.println("  Bytes    : " + s.bytes);
        if (filter != null) System.out.println("  Filter   : " + filter);
        if (s.firstSeen != null) System.out.println("  From     : " + s.firstSeen);
        if (s.lastSeen  != null) System.out.println("  To       : " + s.lastSeen);
        System.out.println();
        System.out.println(BOLD + "Protocols:" + RESET);
        topN(s.protoCounts, 10).forEach((k, v) -> System.out.printf("  %-12s %d%n", k, v));
        System.out.println();
        System.out.println(BOLD + "Top Sources:" + RESET);
        topN(s.srcCounts, 5).forEach((k, v) -> System.out.printf("  %-40s %d%n", k, v));
        System.out.println();
        System.out.println(BOLD + "Top Destinations:" + RESET);
        topN(s.dstCounts, 5).forEach((k, v) -> System.out.printf("  %-40s %d%n", k, v));
        if (!s.ja3Counts.isEmpty()) {
            System.out.println();
            System.out.println(BOLD + "JA3 Fingerprints:" + RESET);
            topN(s.ja3Counts, 10).forEach((k, v) -> System.out.printf("  %s  (%d)%n", k, v));
        }
    }

    static void printJson(Summary s, String filter, long network) {
        System.out.println("{");
        System.out.println("  \"total\": " + s.total + ",");
        System.out.println("  \"bytes\": " + s.bytes + ",");
        System.out.println("  \"filter\": " + jsonStr(filter) + ",");
        System.out.println("  \"linktype\": " + network + ",");
        System.out.println("  \"protocols\": {");
        printJsonMap(s.protoCounts);
        System.out.println("  },");
        System.out.println("  \"top_sources\": {");
        printJsonMap(topN(s.srcCounts, 10));
        System.out.println("  },");
        System.out.println("  \"top_destinations\": {");
        printJsonMap(topN(s.dstCounts, 10));
        System.out.println("  },");
        System.out.println("  \"ja3_fingerprints\": {");
        printJsonMap(s.ja3Counts);
        System.out.println("  }");
        System.out.println("}");
    }

    static void printJsonMap(Map<String, Long> m) {
        var entries = new ArrayList<>(m.entrySet());
        for (int i = 0; i < entries.size(); i++) {
            var e = entries.get(i);
            System.out.print("    " + jsonStr(e.getKey()) + ": " + e.getValue());
            System.out.println(i < entries.size() - 1 ? "," : "");
        }
    }

    static String jsonStr(String s) { return s == null ? "null" : "\"" + s.replace("\"", "\\\"") + "\""; }

    // ─────────────────────────── MD5 (zero deps) ───────────────────────────

    /**
     * Pure-Java MD5 implementation — no MessageDigest, no external libraries.
     * Conforms to RFC 1321. Produces lowercase hex digest.
     */
    static String md5hex(byte[] input) {
        int[] S = {
            7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
            5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
            4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
            6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
        };
        long[] K = new long[64];
        for (int i = 0; i < 64; i++)
            K[i] = (long)(Math.abs(Math.sin(i + 1)) * 0x1_0000_0000L);

        // Pad message to 64-byte boundary: append 0x80, zeros, then 8-byte little-endian bit length
        int origLen = input.length;
        int padLen  = (origLen % 64 < 56) ? 56 - origLen % 64 : 120 - origLen % 64;
        byte[] msg  = new byte[origLen + padLen + 8];
        System.arraycopy(input, 0, msg, 0, origLen);
        msg[origLen] = (byte) 0x80;
        long bitLen  = (long) origLen * 8;
        for (int i = 0; i < 8; i++) msg[origLen + padLen + i] = (byte)(bitLen >>> (8 * i));

        int a0 = 0x67452301;
        int b0 = (int) 0xEFCDAB89L;
        int c0 = (int) 0x98BADCFEL;
        int d0 = 0x10325476;

        for (int chunk = 0; chunk < msg.length; chunk += 64) {
            int[] M = new int[16];
            for (int j = 0; j < 16; j++) {
                int o = chunk + j * 4;
                M[j] = (msg[o] & 0xFF)
                     | ((msg[o+1] & 0xFF) << 8)
                     | ((msg[o+2] & 0xFF) << 16)
                     | ((msg[o+3] & 0xFF) << 24);
            }
            int A = a0, B = b0, C = c0, D = d0;
            for (int i = 0; i < 64; i++) {
                int F, g;
                if      (i < 16) { F = (B & C) | (~B & D); g = i; }
                else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
                else if (i < 48) { F = B ^ C ^ D;           g = (3 * i + 5) % 16; }
                else             { F = C ^ (B | ~D);         g = (7 * i)     % 16; }
                F += A + (int) K[i] + M[g];
                A = D; D = C; C = B;
                B += Integer.rotateLeft(F, S[i]);
            }
            a0 += A; b0 += B; c0 += C; d0 += D;
        }

        return String.format("%08x%08x%08x%08x",
            Integer.reverseBytes(a0),
            Integer.reverseBytes(b0),
            Integer.reverseBytes(c0),
            Integer.reverseBytes(d0));
    }

    // ─────────────────────────── HELPERS ───────────────────────────

    static String linktypeName(long n) {
        return switch ((int) n) {
            case 0   -> "NULL/Loopback";
            case 1   -> "Ethernet";
            case 113 -> "Linux Cooked (SLL)";
            default  -> String.valueOf(n);
        };
    }

    static boolean has(String[] args, String opt) {
        for (String a : args) if (a.equals(opt)) return true;
        return false;
    }

    static int u16be(byte[] b, int o) {
        return ((b[o] & 0xFF) << 8) | (b[o+1] & 0xFF);
    }

    static int u16(byte[] b, int o, boolean big) {
        return big ? u16be(b, o) : ((b[o] & 0xFF) | ((b[o+1] & 0xFF) << 8));
    }

    static long u32(byte[] b, int o, boolean big) {
        if (big)
            return (((long) b[o]   & 0xFF) << 24)
                 | (((long) b[o+1] & 0xFF) << 16)
                 | (((long) b[o+2] & 0xFF) <<  8)
                 |  ((long) b[o+3] & 0xFF);
        return  ((long) b[o]   & 0xFF)
              | (((long) b[o+1] & 0xFF) <<  8)
              | (((long) b[o+2] & 0xFF) << 16)
              | (((long) b[o+3] & 0xFF) << 24);
    }

    static int u32be(byte[] b, int o) {
        return (int) u32(b, o, true);
    }

    static String ipv4(byte[] b, int o) {
        return (b[o]&0xFF) + "." + (b[o+1]&0xFF) + "." + (b[o+2]&0xFF) + "." + (b[o+3]&0xFF);
    }

    static String ipv6(byte[] b, int o) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i += 2) {
            if (i > 0) sb.append(':');
            sb.append(Integer.toHexString(u16be(b, o + i)));
        }
        return sb.toString();
    }

    static String padRight(String s, int n) {
        if (s.length() >= n) return s.substring(0, n);
        return s + " ".repeat(n - s.length());
    }

    static void w16(OutputStream os, long v, boolean big) throws IOException {
        if (big) { os.write((int)(v >> 8) & 0xFF); os.write((int) v & 0xFF); }
        else     { os.write((int) v & 0xFF);        os.write((int)(v >> 8) & 0xFF); }
    }

    static void w32(OutputStream os, long v, boolean big) throws IOException {
        if (big) {
            os.write((int)(v >> 24) & 0xFF); os.write((int)(v >> 16) & 0xFF);
            os.write((int)(v >>  8) & 0xFF); os.write((int) v        & 0xFF);
        } else {
            os.write((int) v        & 0xFF); os.write((int)(v >>  8) & 0xFF);
            os.write((int)(v >> 16) & 0xFF); os.write((int)(v >> 24) & 0xFF);
        }
    }

    static Map<String, Long> topN(Map<String, Long> map, int n) {
        return map.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(n)
            .collect(Collectors.toMap(
                Map.Entry::getKey, Map.Entry::getValue,
                (a, b) -> a, LinkedHashMap::new));
    }
}
