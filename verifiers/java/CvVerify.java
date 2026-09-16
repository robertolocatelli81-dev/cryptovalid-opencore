// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roberto Locatelli
//
// CvVerify — independent Java verifier of the cryptovalid evidence-ledger profile (spec/CONFORMANCE.md), JDK
// standard library only (no dependencies): strict JSON per the acceptance profile (nesting <= 512, no floats,
// no duplicate keys, no lone surrogates, integers within +/-(2^53-1)), canonical JSON identical byte for byte to
// Python json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True), SHA-256 / SHA3-256 hash chain,
// per-entry Ed25519 (JDK 15+) and ML-DSA-65 (JDK 24+, FIPS 204, EMPTY context — JEP 497 has no context API,
// which is why the profile uses none) signatures, and the signed chain tip (cryptovalid_tip/1), with the SAME
// tri-state and rules as signer.py / cvverify (Go). Run:  java CvVerify.java <ledger.jsonl> [flags]  (JDK 24+)
//   flags: -tip F -trusted-pubkey HEX -trusted-pq-pubkey B64 -require-tip -tip-not-before ISO -expect-ledger-id HEX
//          -pubkey HEX -pq-pubkey B64 -require-pq
// Exit 0 = PASS, 1 = FAIL, 2 = usage. Output: one JSON receipt (fields named as the Go verifier's).
import java.io.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.regex.*;

public class CvVerify {
    static final int MAX_DEPTH = 512;
    static final long SAFE_INT = (1L << 53) - 1;
    static final long MAX_INPUT_BYTES = 256L * 1024 * 1024;   // verifier.py MAX_INPUT_BYTES
    static final String GENESIS = "0".repeat(64);
    static final String TIP_KIND = "cryptovalid_tip/1";
    static final Set<String> ATTEST = Set.of("self_hash", "signature", "signer", "signature_pq", "signer_pq");
    static final byte[] ED_SPKI = hex("302a300506032b6570032100");
    static final byte[] MLDSA65_SPKI = hex("308207b2300b0609608648016503040312038207a100");
    static final Pattern TS = Pattern.compile("^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})$");
    static final String SCOPE = "single-snapshot check of the cryptovalid profile: self_hash recompute, prev_hash linkage, sequential idx, genesis; entry signatures and the signed chain tip when asked. Does NOT see a truncated tail unless a signed chain tip is checked.";

    // ───────────────────────── strict JSON (acceptance profile) ─────────────────────────
    static final class Obj { final List<String> keys = new ArrayList<>(); final Map<String, Object> vals = new HashMap<>(); }
    static final class Num { final String lexeme; Num(String s) { lexeme = s; } }
    static final class Bad extends Exception { Bad(String m) { super(m); } }

    static int nestingDepth(byte[] t) {
        int depth = 0, max = 0; boolean inStr = false, esc = false;
        for (byte b : t) {
            char c = (char) (b & 0xff);
            if (inStr) { if (esc) esc = false; else if (c == '\\') esc = true; else if (c == '"') inStr = false; }
            else if (c == '"') inStr = true;
            else if (c == '[' || c == '{') { depth++; if (depth > max) max = depth; }
            else if (c == ']' || c == '}') depth--;
        }
        return max;
    }

    static boolean hasLoneSurrogate(byte[] t) {
        int i = 0, n = t.length;
        while (i < n) {
            if (t[i] != '\\') { i++; continue; }
            if (i + 1 < n && t[i + 1] == 'u' && i + 5 < n) {
                Integer cp = hex4(t, i + 2);
                if (cp == null) { i += 2; continue; }
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (i + 7 >= n || t[i + 6] != '\\' || t[i + 7] != 'u') return true;
                    Integer lo = hex4(t, i + 8);
                    if (lo == null || lo < 0xDC00 || lo > 0xDFFF) return true;
                    i += 12; continue;
                }
                if (cp >= 0xDC00 && cp <= 0xDFFF) return true;
                i += 6; continue;
            }
            i += 2;
        }
        return false;
    }
    static Integer hex4(byte[] t, int at) {   // 4 ASCII hex digits or null — never Integer.parseInt (it takes a sign and Unicode digits: r5)
        if (at + 4 > t.length) return null;
        int v = 0;
        for (int k = 0; k < 4; k++) { int d = hexDigit((char) (t[at + k] & 0xff)); if (d < 0) return null; v = (v << 4) | d; }
        return v;
    }
    static int hexDigit(char c) { return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1; }

    static Object parse(byte[] text) throws Bad {
        String s;
        try { s = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(text)).toString(); }
        catch (CharacterCodingException e) { throw new Bad("non-UTF-8 input"); }
        int d = nestingDepth(text);
        if (d > MAX_DEPTH) throw new Bad("json_too_deep: nesting " + d + " exceeds the acceptance-profile bound " + MAX_DEPTH);
        if (hasLoneSurrogate(text)) throw new Bad("lone_surrogate: unpaired UTF-16 surrogate escape is outside the acceptance profile");
        Parser p = new Parser(s);
        p.ws(); Object v = p.value(); p.ws();
        if (p.i != s.length()) throw new Bad("trailing data after JSON value");
        return v;
    }

    static final class Parser {
        final String s; int i = 0;
        Parser(String s) { this.s = s; }
        void ws() { while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == '\t' || s.charAt(i) == '\n' || s.charAt(i) == '\r')) i++; }
        char peek() throws Bad { if (i >= s.length()) throw new Bad("unexpected end of JSON"); return s.charAt(i); }
        Object value() throws Bad {
            char c = peek();
            switch (c) {
                case '{': return object();
                case '[': return array();
                case '"': return string();
                case 't': lit("true"); return Boolean.TRUE;
                case 'f': lit("false"); return Boolean.FALSE;
                case 'n': lit("null"); return null;
                default: return number();
            }
        }
        void lit(String w) throws Bad { if (!s.startsWith(w, i)) throw new Bad("invalid literal"); i += w.length(); }
        Obj object() throws Bad {
            Obj o = new Obj(); i++; ws();
            if (peek() == '}') { i++; return o; }
            while (true) {
                ws(); if (peek() != '"') throw new Bad("object key is not a string");
                String k = string(); ws();
                if (peek() != ':') throw new Bad("expected ':'"); i++; ws();
                Object v = value();
                if (o.vals.containsKey(k)) throw new Bad("duplicate key \"" + k + "\"");
                o.keys.add(k); o.vals.put(k, v); ws();
                char c = peek(); i++;
                if (c == '}') return o;
                if (c != ',') throw new Bad("expected ',' or '}'");
            }
        }
        List<Object> array() throws Bad {
            List<Object> a = new ArrayList<>(); i++; ws();
            if (peek() == ']') { i++; return a; }
            while (true) {
                ws(); a.add(value()); ws();
                char c = peek(); i++;
                if (c == ']') return a;
                if (c != ',') throw new Bad("expected ',' or ']'");
            }
        }
        String string() throws Bad {
            StringBuilder b = new StringBuilder(); i++;
            while (true) {
                char c = peek(); i++;
                if (c == '"') return b.toString();
                if (c < 0x20) throw new Bad("control character in string");
                if (c != '\\') { b.append(c); continue; }
                char e = peek(); i++;
                switch (e) {
                    case '"': b.append('"'); break; case '\\': b.append('\\'); break; case '/': b.append('/'); break;
                    case 'b': b.append('\b'); break; case 'f': b.append('\f'); break; case 'n': b.append('\n'); break;
                    case 'r': b.append('\r'); break; case 't': b.append('\t'); break;
                    case 'u': {
                        if (i + 4 > s.length()) throw new Bad("bad \\u escape");
                        int v = 0;
                        for (int k = 0; k < 4; k++) { int d = hexDigit(s.charAt(i + k)); if (d < 0) throw new Bad("bad \\u escape"); v = (v << 4) | d; }
                        b.append((char) v); i += 4; break;
                    }
                    default: throw new Bad("bad escape");
                }
            }
        }
        Num number() throws Bad {
            int st = i;
            if (i < s.length() && s.charAt(i) == '-') i++;
            if (i >= s.length() || !Character.isDigit(s.charAt(i)) || s.charAt(i) > '9') throw new Bad("invalid number");
            if (s.charAt(i) == '0') i++; else while (i < s.length() && s.charAt(i) >= '0' && s.charAt(i) <= '9') i++;
            String lex = s.substring(st, i);
            if (i < s.length() && (s.charAt(i) == '.' || s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                int j = i; while (j < s.length() && "0123456789.eE+-".indexOf(s.charAt(j)) >= 0) j++;
                throw new Bad("floating-point number \"" + s.substring(st, j) + "\" is forbidden by the profile");
            }
            if (lex.equals("-0")) lex = "0";
            try { long v = Long.parseLong(lex); if (v > SAFE_INT || v < -SAFE_INT) throw new Bad("integer " + lex + " outside the portable range +/-(2^53-1)"); }
            catch (NumberFormatException x) { throw new Bad("integer " + lex + " outside the portable range +/-(2^53-1)"); }
            return new Num(lex);
        }
    }

    // ───────────────────────── canonical JSON (Python ensure_ascii, sorted keys by code point) ─────────────────────────
    static final Comparator<String> BY_CODEPOINT = (a, b) -> {
        int[] x = a.codePoints().toArray(), y = b.codePoints().toArray();
        for (int k = 0; k < Math.min(x.length, y.length); k++) if (x[k] != y[k]) return Integer.compare(x[k], y[k]);
        return Integer.compare(x.length, y.length);
    };
    static void encode(StringBuilder b, Object v) {
        if (v == null) b.append("null");
        else if (v instanceof Boolean) b.append(((Boolean) v) ? "true" : "false");
        else if (v instanceof Num) b.append(((Num) v).lexeme);
        else if (v instanceof String) writeString(b, (String) v);
        else if (v instanceof List) { b.append('['); List<?> l = (List<?>) v; for (int k = 0; k < l.size(); k++) { if (k > 0) b.append(','); encode(b, l.get(k)); } b.append(']'); }
        else if (v instanceof Obj) {
            Obj o = (Obj) v; List<String> ks = new ArrayList<>(o.keys); ks.sort(BY_CODEPOINT); b.append('{');
            for (int k = 0; k < ks.size(); k++) { if (k > 0) b.append(','); writeString(b, ks.get(k)); b.append(':'); encode(b, o.vals.get(ks.get(k))); }
            b.append('}');
        } else throw new IllegalStateException("unsupported value");
    }
    static void writeString(StringBuilder b, String s) {
        b.append('"');
        s.codePoints().forEach(r -> {
            switch (r) {
                case '"': b.append("\\\""); break; case '\\': b.append("\\\\"); break; case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break; case '\t': b.append("\\t"); break; case '\b': b.append("\\b"); break; case '\f': b.append("\\f"); break;
                default:
                    if (r >= 0x20 && r <= 0x7e) b.append((char) r);
                    else if (r > 0xFFFF) { int q = r - 0x10000; b.append(String.format("\\u%04x\\u%04x", 0xD800 + (q >> 10), 0xDC00 + (q & 0x3FF))); }
                    else b.append(String.format("\\u%04x", r));
            }
        });
        b.append('"');
    }
    static byte[] payload(Obj e) {
        Obj cp = new Obj();
        for (String k : e.keys) if (!ATTEST.contains(k)) { cp.keys.add(k); cp.vals.put(k, e.vals.get(k)); }
        StringBuilder b = new StringBuilder(); encode(b, cp); return b.toString().getBytes(StandardCharsets.UTF_8);
    }
    static String hash(String algo, byte[] p) throws Exception {
        return toHex(MessageDigest.getInstance(algo.equals("sha256") ? "SHA-256" : "SHA3-256").digest(p));
    }

    // ───────────────────────── helpers ─────────────────────────
    static byte[] hex(String s) { byte[] o = new byte[s.length() / 2]; for (int k = 0; k < o.length; k++) o[k] = (byte) Integer.parseInt(s.substring(2 * k, 2 * k + 2), 16); return o; }
    static String toHex(byte[] b) { StringBuilder sb = new StringBuilder(); for (byte x : b) sb.append(String.format("%02x", x)); return sb.toString(); }
    static boolean isHexN(String s, int n) { if (s == null || s.length() != n) return false; for (char c : s.toCharArray()) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false; return true; }
    static byte[] b64Strict(String s, int n) {
        if (s == null || s.length() != ((n + 2) / 3) * 4 || !s.matches("[A-Za-z0-9+/]*={0,2}")) return null;
        try { byte[] raw = Base64.getDecoder().decode(s); return raw.length == n && Base64.getEncoder().encodeToString(raw).equals(s) ? raw : null; } catch (Exception e) { return null; }
    }
    static PublicKey key(String alg, byte[] hdr, byte[] raw) throws Exception {
        byte[] spki = new byte[hdr.length + raw.length]; System.arraycopy(hdr, 0, spki, 0, hdr.length); System.arraycopy(raw, 0, spki, hdr.length, raw.length);
        return KeyFactory.getInstance(alg).generatePublic(new X509EncodedKeySpec(spki));
    }
    static boolean edVerify(byte[] pk, byte[] msg, byte[] sig) { try { Signature v = Signature.getInstance("Ed25519"); v.initVerify(key("Ed25519", ED_SPKI, pk)); v.update(msg); return v.verify(sig); } catch (Exception e) { return false; } }
    static Boolean mldsaSupported() { try { Signature.getInstance("ML-DSA-65"); return true; } catch (Exception e) { return false; } }
    static boolean mldsaVerify(byte[] pk, byte[] msg, byte[] sig) { try { Signature v = Signature.getInstance("ML-DSA-65"); v.initVerify(key("ML-DSA", MLDSA65_SPKI, pk)); v.update(msg); return v.verify(sig); } catch (Exception e) { return false; } }

    // ───────────────────────── instants (same value profile as Python/JS/Go) ─────────────────────────
    static long[] parseInstant(String s) throws Bad {   // (epoch seconds, nanos) or Bad
        Matcher m = TS.matcher(s == null ? "" : s);
        if (!m.matches()) throw new Bad("timestamp outside the profile YYYY-MM-DDThh:mm:ss[.fraction](Z|±hh:mm)");
        int y = Integer.parseInt(m.group(1)), mo = Integer.parseInt(m.group(2)), d = Integer.parseInt(m.group(3));
        int h = Integer.parseInt(m.group(4)), mi = Integer.parseInt(m.group(5)), sec = Integer.parseInt(m.group(6));
        if (y < 1 || y > 9999 || mo < 1 || mo > 12 || h > 23 || mi > 59 || sec > 59) throw new Bad("timestamp field out of range");
        boolean leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        int dim = new int[]{31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[mo - 1];
        if (d < 1 || d > dim) throw new Bad("timestamp day does not exist in that month");
        int off = 0;
        if (!m.group(8).equals("Z")) {
            int oh = Integer.parseInt(m.group(8).substring(1, 3)), om = Integer.parseInt(m.group(8).substring(4, 6));
            if (oh > 23 || om > 59) throw new Bad("timestamp offset out of range");
            off = oh * 3600 + om * 60; if (m.group(8).charAt(0) == '-') off = -off;
        }
        long nanos = m.group(7) == null ? 0 : Long.parseLong((m.group(7) + "000000000").substring(0, 9));
        long days = java.time.LocalDate.of(y, mo, d).toEpochDay();
        return new long[]{days * 86400L + h * 3600L + mi * 60L + sec - off, nanos};
    }
    static boolean before(long[] a, long[] b) { return a[0] < b[0] || (a[0] == b[0] && a[1] < b[1]); }

    // ───────────────────────── receipt (minimal JSON writer) ─────────────────────────
    static String j(Object v) {
        if (v == null) return "null";
        if (v instanceof Boolean || v instanceof Integer || v instanceof Long) return String.valueOf(v);
        if (v instanceof String) { StringBuilder b = new StringBuilder(); writeString(b, (String) v); return b.toString(); }
        if (v instanceof List) { StringBuilder b = new StringBuilder("["); List<?> l = (List<?>) v; for (int k = 0; k < l.size(); k++) { if (k > 0) b.append(","); b.append(j(l.get(k))); } return b.append("]").toString(); }
        if (v instanceof Map) { StringBuilder b = new StringBuilder("{"); boolean first = true; for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) { if (!first) b.append(","); first = false; b.append(j(e.getKey())).append(":").append(j(e.getValue())); } return b.append("}").toString(); }
        return "\"?\"";
    }

    // ───────────────────────── the verdict ─────────────────────────
    public static void main(String[] args) {
        try { run(args); }
        catch (Throwable t) {   // never a stack trace: a JSON FAIL receipt (r5: Path NUL bytes, OOM)
            System.out.println("{\"verdict\":\"FAIL\",\"failures\":[\"internal: " + t.getClass().getSimpleName() + "\"],\"scope\":\"" + SCOPE.replace("\"", "'") + "\"}");
            System.exit(1);
        }
    }
    static void run(String[] args) throws Exception {
        String ledger = null, tip = "", tpk = "", tpq = "", nb = "", lid = "", epk = "", epq = ""; boolean reqTip = false, reqPQ = false;
        for (int k = 0; k < args.length; k++) {
            String a = args[k];
            try {
                switch (a) {
                    case "-tip": tip = args[++k]; break; case "-trusted-pubkey": tpk = args[++k]; break; case "-trusted-pq-pubkey": tpq = args[++k]; break;
                    case "-tip-not-before": nb = args[++k]; break; case "-expect-ledger-id": lid = args[++k]; break; case "-pubkey": epk = args[++k]; break;
                    case "-pq-pubkey": epq = args[++k]; break; case "-require-tip": reqTip = true; break; case "-require-pq": reqPQ = true; break;
                    default: if (a.startsWith("-") || ledger != null) { usage(); return; } ledger = a;
                }
            } catch (ArrayIndexOutOfBoundsException e) { usage(); return; }
        }
        if (ledger == null) { usage(); return; }
        Map<String, Object> out = verify(ledger, tip, tpk, tpq, epk, epq, reqPQ, reqTip, nb, lid);
        System.out.println(j(out));
        System.exit("PASS".equals(out.get("verdict")) ? 0 : 1);
    }
    static void usage() { System.err.println("usage: java CvVerify.java <ledger.jsonl> [-tip F] [-trusted-pubkey HEX] [-trusted-pq-pubkey B64] [-require-tip] [-tip-not-before ISO] [-expect-ledger-id HEX] [-pubkey HEX] [-pq-pubkey B64] [-require-pq]"); System.exit(2); }

    static Map<String, Object> verify(String ledgerPath, String tipPath, String tpk, String tpq, String epk, String epq, boolean reqPQ, boolean reqTip, String nb, String lid) throws Exception {
        Map<String, Object> v = new LinkedHashMap<>(); List<String> failures = new ArrayList<>();
        List<Obj> objects = new ArrayList<>();
        boolean hashOK = true, linkOK = true; String algo = ""; String prev = GENESIS, first = ""; int i = 0, line = 0;
        List<byte[]> lines = new ArrayList<>();
        try {
            if (Files.size(Path.of(ledgerPath)) > MAX_INPUT_BYTES) {   // fail-closed on size, like verifier.py (r5)
                v.put("verdict", "FAIL"); v.put("failures", List.of("input_too_large: file exceeds " + MAX_INPUT_BYTES + " bytes")); v.put("scope", SCOPE); return v;
            }
            try (InputStream in = new BufferedInputStream(Files.newInputStream(Path.of(ledgerPath)), 1 << 16)) {
                ByteArrayOutputStream cur = new ByteArrayOutputStream(); int c;
                while ((c = in.read()) >= 0) { if (c == '\n') { lines.add(cur.toByteArray()); cur.reset(); } else cur.write(c); }
                if (cur.size() > 0) lines.add(cur.toByteArray());
            }
        } catch (IOException | RuntimeException e) { v.put("verdict", "FAIL"); v.put("failures", List.of("open: " + e.getClass().getSimpleName())); v.put("scope", SCOPE); return v; }
        for (byte[] raw : lines) {
            line++;
            if (isBlank(raw)) continue;   // blank = ASCII space/tab/CR only
            Object val;
            try { val = parse(raw); } catch (Bad e) { failures.add("line " + line + ": " + e.getMessage()); hashOK = false; objects.add(null); i++; continue; }
            if (!(val instanceof Obj)) { failures.add("line " + line + ": entry is not an object"); hashOK = false; objects.add(null); i++; continue; }
            Obj e = (Obj) val; objects.add(e);
            Object shv = e.vals.get("self_hash"); String self = shv instanceof String ? (String) shv : null;
            if (algo.isEmpty()) {   // no early return (r5): fall back to sha256 like the Python reference and keep going
                byte[] p0 = payload(e);
                if (self != null && self.length() == 64) for (String a : new String[]{"sha256", "sha3_256"}) if (hash(a, p0).equals(self)) algo = a;
                if (algo.isEmpty()) { failures.add("entry " + i + ": self_hash matches no supported profile"); hashOK = false; algo = "sha256"; }
            }
            Object idx = e.vals.get("idx");
            if (!(idx instanceof Num) || !((Num) idx).lexeme.equals(String.valueOf(i))) { linkOK = false; failures.add("entry " + i + ": idx \"" + (idx instanceof Num ? ((Num) idx).lexeme : "") + "\" not sequential"); }
            if (self == null || self.length() != 64) { hashOK = false; failures.add("entry " + i + ": self_hash missing or not a 64-hex string"); }
            else if (!hash(algo, payload(e)).equals(self)) { hashOK = false; failures.add("entry " + i + ": self_hash mismatch"); }
            Object pv = e.vals.get("prev_hash");
            if (!(pv instanceof String) || !pv.equals(prev)) { linkOK = false; failures.add("entry " + i + ": prev_hash does not link"); }
            if (i == 0) first = self == null ? "" : self;
            prev = self == null ? "" : self; i++;
        }
        if (i == 0) { failures.add("line 0: empty_ledger: zero entries, nothing to verify"); hashOK = false; }
        boolean pass = hashOK && linkOK && failures.isEmpty();
        v.put("verdict", pass ? "PASS" : "FAIL"); v.put("algo", algo); v.put("entries_count", i);
        v.put("hash_recompute_passed", hashOK); v.put("link_passed", linkOK); v.put("failures", failures);
        if (!first.isEmpty()) v.put("first_self_hash", first); if (i > 0) v.put("last_self_hash", prev);

        // per-entry signatures (same rules as signer.py / Go VerifyLedgerFull)
        if (reqPQ && epq.isEmpty()) { failures.add("require_pq_without_key: -require-pq needs -pq-pubkey (a post-quantum layer verified against the key inside the ledger is self-declared)"); v.put("verdict", "FAIL"); v.put("scope", SCOPE); return v; }
        if (!epq.isEmpty() && epk.isEmpty()) { failures.add("pq_key_without_ed25519_key: -pq-pubkey needs -pubkey (hybrid means both keys are pinned)"); v.put("verdict", "FAIL"); v.put("scope", SCOPE); return v; }
        boolean hasSig = false; for (Obj o : objects) if (o != null && o.vals.containsKey("signature")) { hasSig = true; break; }
        if (hasSig || !epk.isEmpty() || !epq.isEmpty()) {
            Map<String, Object> sc = signatures(objects, epk, epq, reqPQ);
            v.put("signatures", sc);
            Object pqp = sc.get("pq_protected");
            if ((!epk.isEmpty() || !epq.isEmpty()) && (!(Boolean) sc.get("ok") || (!epq.isEmpty() && !Boolean.TRUE.equals(pqp)))) {
                v.put("verdict", "FAIL"); failures.add("signatures_failed: the pinned signature layer does not verify (" + sc.get("pq_status") + ")");
            }
        }
        // signed chain tip
        if (!tpq.isEmpty()) { reqTip = true; if (tpk.isEmpty()) { failures.add("pq_key_without_log_key: -trusted-pq-pubkey needs -trusted-pubkey (the post-quantum layer sits on top of the Ed25519 tip, never instead of it)"); v.put("verdict", "FAIL"); v.put("scope", SCOPE); return v; } }
        if (tipPath.isEmpty() && Files.exists(Path.of(ledgerPath + ".tip.json"))) tipPath = ledgerPath + ".tip.json";
        if (tipPath.isEmpty()) {
            if (reqTip) { v.put("verdict", "FAIL"); failures.add("tip_missing: a signed chain tip is required and none was found"); }
        } else {
            Map<String, Object> tc = new LinkedHashMap<>(); tc.put("ok", false); tc.put("checked", false);
            if (tpk.isEmpty()) {
                tc.put("why", "tip_untrusted: a signed tip is present but no trusted log key was given (-trusted-pubkey); the tail limit applies in full"); tc.put("trusted", false); tc.put("tip_path", tipPath); tc.put("pq_protected", null);
                if (reqTip) { v.put("verdict", "FAIL"); failures.add("entry " + i + ": " + tc.get("why")); }
            } else {
                tc = checkTip(tipPath, i, first.isEmpty() ? GENESIS : first, i == 0 ? GENESIS : prev, tpk, tpq, nb, lid);
                if (!(Boolean) tc.get("ok")) { v.put("verdict", "FAIL"); failures.add("entry " + i + ": " + tc.get("why")); }
            }
            v.put("tip", tc);
        }
        v.put("scope", SCOPE);
        return v;
    }
    static boolean isBlank(byte[] raw) { for (byte b : raw) if (b != ' ' && b != '\t' && b != '\r') return false; return true; }
    static Map<String, Object> fail(Map<String, Object> v, String algo, int n, List<String> failures) { v.put("verdict", "FAIL"); v.put("algo", algo); v.put("entries_count", n); v.put("hash_recompute_passed", false); v.put("link_passed", true); v.put("failures", failures); v.put("scope", SCOPE); return v; }

    static Map<String, Object> signatures(List<Obj> entries, String epk, String epq, boolean reqPQ) {
        Map<String, Object> sc = new LinkedHashMap<>(); List<String> fails = new ArrayList<>(), pqFails = new ArrayList<>();
        Set<String> signers = new TreeSet<>(), pqSigners = new TreeSet<>();   // sorted, as Python/Go
        boolean require = reqPQ || !epq.isEmpty(); boolean pqOK = mldsaSupported();
        int verified = 0, pqVerified = 0, pqPresent = 0, pqUnver = 0;
        for (int k = 0; k < entries.size(); k++) {
            Obj e = entries.get(k);
            String sig = e == null ? null : (e.vals.get("signature") instanceof String ? (String) e.vals.get("signature") : null);
            String signer = e == null ? null : (e.vals.get("signer") instanceof String ? (String) e.vals.get("signer") : null);
            String sh = e == null ? null : (e.vals.get("self_hash") instanceof String ? (String) e.vals.get("self_hash") : null);
            if (sig == null || signer == null || sh == null || sig.isEmpty() || signer.isEmpty() || sh.isEmpty()) { fails.add("idx " + k + ": missing signature/signer/self_hash"); continue; }
            if (!epk.isEmpty() && !signer.equals(epk)) { fails.add("idx " + k + ": signer_mismatch"); continue; }
            byte[] rawSig = b64Strict(sig, 64);
            if (rawSig == null || !isHexN(signer, 64)) { fails.add("idx " + k + ": malformed_signature_field"); continue; }
            if (edVerify(hex(signer), sh.getBytes(StandardCharsets.UTF_8), rawSig)) { verified++; signers.add(signer); } else fails.add("idx " + k + ": bad_signature");
            boolean hasS = e.vals.containsKey("signature_pq"), hasK = e.vals.containsKey("signer_pq");
            if (!hasS && !hasK) { if (require) pqFails.add("idx " + k + ": pq_missing"); continue; }
            pqPresent++;
            Object ps = e.vals.get("signature_pq"), pk = e.vals.get("signer_pq");
            if (!(ps instanceof String) || !(pk instanceof String) || ((String) ps).isEmpty() || ((String) pk).isEmpty()) { pqFails.add("idx " + k + ": missing signature_pq/signer_pq"); continue; }
            if (!epq.isEmpty() && !pk.equals(epq)) { pqFails.add("idx " + k + ": pq_signer_mismatch"); continue; }
            byte[] rs = b64Strict((String) ps, 3309), rk = b64Strict((String) pk, 1952);
            if (rs == null || rk == null) { pqFails.add("idx " + k + ": malformed_pq_field"); continue; }
            if (!pqOK) { pqUnver++; if (require) pqFails.add("idx " + k + ": pq_unverifiable"); continue; }
            if (mldsaVerify(rk, sh.getBytes(StandardCharsets.UTF_8), rs)) { pqVerified++; pqSigners.add((String) pk); } else pqFails.add("idx " + k + ": bad_pq_signature");
        }
        Boolean prot; String status, note;
        boolean allUnver = !pqFails.isEmpty() && pqFails.stream().allMatch(x -> x.endsWith("pq_unverifiable"));
        boolean allMissing = !pqFails.isEmpty() && pqFails.stream().allMatch(x -> x.endsWith("pq_missing"));
        if (allUnver) { prot = null; status = "unverifiable"; note = "post-quantum layer required but ML-DSA-65 cannot be verified here (JDK < 24): not a pass"; }
        else if (!pqFails.isEmpty()) { prot = false; status = allMissing ? "missing" : "invalid"; note = allMissing ? "post-quantum layer required but absent on some entries (stripped or never signed)" : "post-quantum layer invalid, foreign or malformed on some entries"; }
        else if (pqPresent == 0) { prot = false; status = "absent"; note = "no post-quantum signatures (Ed25519 only: not quantum-resistant, NIST IR 8547 draft)"; }
        else if (pqUnver > 0) { prot = null; status = "unverifiable"; note = "ML-DSA-65 signatures present but NOT verified (this JDK has no ML-DSA: needs JDK 24+)"; }
        else if (pqVerified != entries.size() || entries.isEmpty()) { prot = false; status = "partial"; note = "post-quantum signatures on some entries only: not a protected ledger"; }
        else if (!fails.isEmpty()) { prot = false; status = "classical_broken"; note = "ML-DSA-65 signatures valid but an Ed25519 signature is not: hybrid means BOTH hold"; }
        else if (epq.isEmpty()) { prot = null; status = "unpinned"; note = "ML-DSA-65 signatures verified against the EMBEDDED key only (anyone can add their own): pass -pq-pubkey to pin"; }
        else { prot = true; status = "protected"; note = "hybrid: every entry carries a valid ML-DSA-65 (FIPS 204) signature by the expected key, besides Ed25519"; }
        sc.put("ok", fails.isEmpty() && verified == entries.size() && !entries.isEmpty() && pqFails.isEmpty());
        sc.put("verified", verified); sc.put("total", entries.size()); sc.put("failures", fails); sc.put("signers", new ArrayList<>(signers));
        sc.put("pq_protected", prot); sc.put("pq_status", status); sc.put("pq_verified", pqVerified); sc.put("pq_failures", pqFails); sc.put("pq_signers", new ArrayList<>(pqSigners)); sc.put("pq_note", note);
        return sc;
    }

    static Map<String, Object> checkTip(String path, int entries, String first, String last, String tpk, String tpq, String nb, String lid) {
        Map<String, Object> tc = new LinkedHashMap<>(); tc.put("ok", false); tc.put("checked", true); tc.put("trusted", false); tc.put("tip_path", path); tc.put("pq_protected", false);
        Obj t;
        try { Object o = parse(Files.readAllBytes(Path.of(path))); if (!(o instanceof Obj)) throw new Bad("not an object"); t = (Obj) o; }
        catch (Exception e) { tc.put("why", "tip_unreadable: " + e.getMessage()); return tc; }
        String kind = str(t, "kind"), ledgerId = str(t, "ledger_id"), tipSha = str(t, "tip_sha256"), ts = str(t, "ts"), sigHex = str(t, "signature_hex"), logPk = str(t, "log_pubkey_hex");
        Object logPkRaw = t.vals.get("log_pubkey_hex");
        if (logPkRaw != null && !(logPkRaw instanceof String)) { tc.put("why", "tip_invalid: tip fields must be strings"); return tc; }   // r5: 123 was skipped
        Object en = t.vals.get("entries"); long n = -1;
        if (en instanceof Num) { try { n = Long.parseLong(((Num) en).lexeme); } catch (Exception e) { n = -1; } }
        if (!TIP_KIND.equals(kind) || !isHexN(sigHex, 128) || !isHexN(tipSha, 64) || !isHexN(ledgerId, 64) || n < 0 || !plainTS(ts)) { tc.put("why", "tip_invalid: not a cryptovalid_tip/1 document"); return tc; }
        boolean pqPresent = t.vals.containsKey("signature_pq_hex") || t.vals.containsKey("log_pq_pubkey_b64");
        String spq = str(t, "signature_pq_hex"), kpq = str(t, "log_pq_pubkey_b64");
        if (pqPresent && (!isHexN(spq, 6618) || b64Strict(kpq, 1952) == null)) { tc.put("why", "tip_invalid: malformed post-quantum fields (signature_pq_hex 6618 lowercase hex, log_pq_pubkey_b64 strict base64 of 1952 bytes)"); return tc; }
        if (logPk != null && !logPk.isEmpty() && !logPk.equals(tpk)) { tc.put("why", "tip_invalid: tip log key differs from the trusted log key"); return tc; }
        byte[] payload = ("{\"entries\":" + n + ",\"kind\":\"" + TIP_KIND + "\",\"ledger_id\":\"" + ledgerId + "\",\"tip_sha256\":\"" + tipSha + "\",\"ts\":\"" + ts + "\"}").getBytes(StandardCharsets.UTF_8);
        if (!isHexN(tpk, 64) || !edVerify(hex(tpk), payload, hex(sigHex))) { tc.put("why", "tip_invalid: tip signature invalid"); return tc; }
        tc.put("trusted", true);
        if (!lid.isEmpty() && !ledgerId.equals(lid)) { tc.put("why", "ledger_id_mismatch: the tip belongs to a different ledger than the one you expect"); return tc; }
        if (entries > 0 && !ledgerId.equals(first)) { tc.put("why", "tip_of_another_ledger: the tip's ledger_id is not this file's first self_hash"); return tc; }
        if (!nb.isEmpty()) {
            long[] nbT; try { nbT = parseInstant(nb); } catch (Bad e) { tc.put("why", "bad_not_before: -tip-not-before must be YYYY-MM-DDThh:mm:ss[.f](Z|±hh:mm)"); return tc; }
            try { if (before(parseInstant(ts), nbT)) { tc.put("why", "tip_rolled_back: the tip is dated " + ts + ", before the required " + nb); return tc; } } catch (Bad e) { tc.put("why", "tip_invalid: ts outside the profile"); return tc; }
        }
        if (entries < n) { tc.put("why", "tail_truncated: file has " + entries + " entries, the signed tip commits to " + n); return tc; }
        if (entries > n) { tc.put("why", "unsealed_tail: file has " + entries + " entries, the signed tip commits to " + n + " (appended after the last signed head)"); return tc; }
        if (!last.equals(tipSha)) { tc.put("why", "tail_rewritten: same entry count but the last self_hash differs from the signed tip"); return tc; }
        tc.put("ok", true); tc.put("why", "tip matches the verified chain");
        // post-quantum layer of the tip (tri-state, same as Python/Go)
        Boolean prot; String pqWhy;
        if (tpq.isEmpty()) { if (spq != null && !spq.isEmpty()) { prot = null; pqWhy = "pq_unchecked: the tip carries an ML-DSA-65 signature but no trusted post-quantum key was given"; } else { prot = false; pqWhy = "pq_absent: Ed25519-only tip (not quantum-resistant)"; } }
        else if (spq == null || spq.isEmpty()) { prot = false; pqWhy = "pq_missing: a trusted ML-DSA-65 key was given but the tip carries no post-quantum signature"; }
        else if (kpq != null && !kpq.isEmpty() && !kpq.equals(tpq)) { prot = false; pqWhy = "tip post-quantum key differs from the trusted one"; }
        else if (b64Strict(tpq, 1952) == null) { prot = false; pqWhy = "bad_trusted_pq_key: -trusted-pq-pubkey must be strict base64 of 1952 bytes"; }
        else if (!mldsaSupported()) { prot = false; pqWhy = "pq_unverifiable: this JDK has no ML-DSA (needs JDK 24+)"; }
        else if (!mldsaVerify(b64Strict(tpq, 1952), payload, hex(spq))) { prot = false; pqWhy = "tip post-quantum signature invalid"; }
        else { prot = true; pqWhy = "ML-DSA-65 signature verified against the trusted post-quantum key"; }
        tc.put("pq_protected", prot); tc.put("pq_why", pqWhy);
        if (!tpq.isEmpty() && !Boolean.TRUE.equals(prot)) { tc.put("ok", false); tc.put("why", tc.get("why") + "; " + pqWhy); }
        return tc;
    }
    static String str(Obj o, String k) { Object v = o.vals.get(k); return v instanceof String ? (String) v : null; }
    static boolean plainTS(String s) { try { parseInstant(s); return true; } catch (Bad e) { return false; } }
}
