// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roberto Locatelli
//
// CvVerify \u2014 independent Java verifier of the cryptovalid evidence-ledger profile (spec/CONFORMANCE.md), JDK
// standard library only (no dependencies): strict JSON per the acceptance profile (nesting <= 512, no floats,
// no duplicate keys, no lone surrogates, integers within +/-(2^53-1)), canonical JSON identical byte for byte to
// Python json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=True), SHA-256 / SHA3-256 hash chain,
// per-entry Ed25519 (JDK 15+) and ML-DSA-65 (JDK 24+, FIPS 204, EMPTY context \u2014 JEP 497 has no context API,
// which is why the profile uses none) signatures, and the signed chain tip (cryptovalid_tip/1), with the SAME
// tri-state and rules as signer.py / cvverify (Go). Run:  java CvVerify.java <ledger.jsonl> [flags]  (JDK 24+)
//   flags: -tip F -trusted-pubkey HEX -trusted-pq-pubkey B64 -require-tip -tip-not-before ISO -expect-ledger-id HEX
//          -pubkey HEX -pq-pubkey B64 -require-pq
// Exit 0 = PASS, 1 = FAIL, 2 = usage, 74 = the receipt was not written whole (stdout full, closed or a reader gone:
// a write to fd 1 that fails; 0.20.3), whatever the verdict. Output: one JSON receipt (fields named as the Go
// verifier's).
// ASCII only (non-ASCII written as Unicode escapes): javac before JDK 18 reads a source in the platform encoding, and on
// Windows the plus-minus and section signs of the texts became other characters (CI run 45437498313, the four verifiers differed)
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
    static final long MAX_INPUT_LINES = 1L << 20, MAX_JSON_TOKENS = 1L << 23;   // SPEC \u00a722 rule 9 (verifier.py MAX_INPUT_LINES, MAX_JSON_TOKENS)
    static long countTokens(byte[] b) { long t = 0; for (byte c : b) if (c == '{' || c == '[' || c == ',' || c == ':') t++; return t; }
    static final String GENESIS = "0".repeat(64);
    static final String TIP_KIND = "cryptovalid_tip/1";
    static final Set<String> TIP_MEMBERS = Set.of("kind", "entries", "ledger_id", "tip_sha256", "ts", "log_pubkey_hex", "signature_hex", "signature_pq_hex", "log_pq_pubkey_b64");
    static final Set<String> ATTEST = Set.of("self_hash", "signature", "signer", "signature_pq", "signer_pq", "tsa_token");   // SPEC \u00a73; tsa_token since 0.20.2
    // SPEC_EVIDENCE_FORMAT \u00a72.1 (2026-10-10): the CLOSED entry schema (core + optional fields of \u00a72), as verifier.py ENTRY_KEYS.
    // A top-level key outside it is the named failure `unknown_field:<keys>`, never a silent PASS (measured 2026-10-11 on this
    // verifier: an extra top-level key with self_hash recomputed over it was PASS with no trace). Keys inside `data` stay free (\u00a74).
    static final Set<String> ENTRY_KEYS = Set.of("idx", "ts", "data", "prev_hash", "self_hash", "signature", "signer", "tsa_token", "signature_pq", "signer_pq");
    static final byte[] ED_SPKI = hex("302a300506032b6570032100");
    static final byte[] MLDSA65_SPKI = hex("308207b2300b0609608648016503040312038207a100");
    static final Pattern TS = Pattern.compile("^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\\.([0-9]{1,9}))?(Z|[+-][0-9]{2}:[0-9]{2})$");
    static final String SCOPE = "single-snapshot check of the cryptovalid profile: self_hash recompute, prev_hash linkage, sequential idx, genesis; entry signatures and the signed chain tip when asked. Does NOT see a truncated tail unless a signed chain tip is checked.";

    // \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 strict JSON (acceptance profile) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
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
    static Integer hex4(byte[] t, int at) {   // 4 ASCII hex digits or null \u2014 never Integer.parseInt (it takes a sign and Unicode digits: r5)
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

    // \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 canonical JSON (Python ensure_ascii, sorted keys by code point) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
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

    // \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 helpers \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
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
    // 0.21.0: Ed25519 points of small and mixed order. The JDK's Ed25519 (RFC 8032 5.1.7, cofactorless) verified a key or an R
    // of small order and a key of mixed order (measured 14/10/2026 on the 12 classes of novifinancial/ed25519-speccheck rebuilt
    // on ledger entries: classes 0-3); the x402 acceptance checker refuses all 12 (b37e471). The key must decode as RFC 8032
    // 5.1.3 says, not be of small order ([8]A neutral) and lie in the subgroup of order L ([L]A neutral); R must decode and
    // not be of small order (with A in the subgroup the cofactorless equation refuses an R of mixed order). BigInteger,
    // not constant time (public values only); the same checks as the Go, JS, Swift and Python code.
    static final java.math.BigInteger EP = java.math.BigInteger.ONE.shiftLeft(255).subtract(java.math.BigInteger.valueOf(19));
    static final java.math.BigInteger EL = java.math.BigInteger.ONE.shiftLeft(252).add(new java.math.BigInteger("27742317777372353535851937790883648493"));
    static final java.math.BigInteger ED = java.math.BigInteger.valueOf(-121665).multiply(java.math.BigInteger.valueOf(121666).modInverse(EP)).mod(EP);
    static final java.math.BigInteger EI = java.math.BigInteger.TWO.modPow(EP.subtract(java.math.BigInteger.ONE).shiftRight(2), EP);
    static java.math.BigInteger[] edDecode(byte[] b) {   // RFC 8032 5.1.3; null when the 32 octets are not a point
        if (b == null || b.length != 32) return null;
        byte[] be = new byte[32]; for (int i = 0; i < 32; i++) be[31 - i] = b[i];
        java.math.BigInteger n = new java.math.BigInteger(1, be);
        boolean x0 = n.testBit(255); java.math.BigInteger y = n.clearBit(255);
        if (y.compareTo(EP) >= 0) return null;
        java.math.BigInteger yy = y.multiply(y).mod(EP), u = yy.subtract(java.math.BigInteger.ONE).mod(EP), v = ED.multiply(yy).add(java.math.BigInteger.ONE).mod(EP);
        java.math.BigInteger v3 = v.modPow(java.math.BigInteger.valueOf(3), EP), v7 = v.modPow(java.math.BigInteger.valueOf(7), EP);
        java.math.BigInteger x = u.multiply(v3).multiply(u.multiply(v7).mod(EP).modPow(EP.subtract(java.math.BigInteger.valueOf(5)).shiftRight(3), EP)).mod(EP);
        java.math.BigInteger vxx = v.multiply(x).multiply(x).mod(EP);
        if (vxx.equals(u)) { } else if (vxx.equals(u.negate().mod(EP))) x = x.multiply(EI).mod(EP); else return null;
        if (x.signum() == 0 && x0) return null;
        if (x.testBit(0) != x0) x = EP.subtract(x);
        return new java.math.BigInteger[]{x, y, java.math.BigInteger.ONE, x.multiply(y).mod(EP)};
    }
    static java.math.BigInteger[] edAdd(java.math.BigInteger[] P, java.math.BigInteger[] Q) {   // RFC 8032 5.1.4
        java.math.BigInteger two = java.math.BigInteger.TWO;
        java.math.BigInteger a = P[1].subtract(P[0]).multiply(Q[1].subtract(Q[0])).mod(EP), b = P[1].add(P[0]).multiply(Q[1].add(Q[0])).mod(EP);
        java.math.BigInteger c = P[3].multiply(two).multiply(ED).multiply(Q[3]).mod(EP), d = P[2].multiply(two).multiply(Q[2]).mod(EP);
        java.math.BigInteger e = b.subtract(a), f = d.subtract(c), g = d.add(c), h = b.add(a);
        return new java.math.BigInteger[]{e.multiply(f).mod(EP), g.multiply(h).mod(EP), f.multiply(g).mod(EP), e.multiply(h).mod(EP)};
    }
    static java.math.BigInteger[] edMul(java.math.BigInteger k, java.math.BigInteger[] P) {
        java.math.BigInteger[] R = {java.math.BigInteger.ZERO, java.math.BigInteger.ONE, java.math.BigInteger.ONE, java.math.BigInteger.ZERO};
        for (int i = k.bitLength() - 1; i >= 0; i--) { R = edAdd(R, R); if (k.testBit(i)) R = edAdd(R, P); }
        return R;
    }
    static boolean edNeutral(java.math.BigInteger[] P) { return P[0].mod(EP).signum() == 0 && P[1].subtract(P[2]).mod(EP).signum() == 0; }
    static String edKeyProblem(byte[] pk) {
        java.math.BigInteger[] A = edDecode(pk);
        if (A == null) return "key_not_decodable";
        if (edNeutral(edMul(java.math.BigInteger.valueOf(8), A))) return "small_order_key";
        if (!edNeutral(edMul(EL, A))) return "mixed_order_key";
        return null;
    }
    static String edRProblem(byte[] sig) {
        java.math.BigInteger[] R = sig != null && sig.length == 64 ? edDecode(Arrays.copyOf(sig, 32)) : null;
        if (R == null) return "r_not_decodable";
        return edNeutral(edMul(java.math.BigInteger.valueOf(8), R)) ? "small_order_r" : null;
    }
    static final Map<String, String> ED_KEY_CACHE = new HashMap<>();
    static String edStrict(byte[] pk, byte[] msg, byte[] sig) {   // null when it verifies, else the reason
        String h = toHex(pk);
        if (!ED_KEY_CACHE.containsKey(h)) ED_KEY_CACHE.put(h, edKeyProblem(pk));
        String kp = ED_KEY_CACHE.get(h); if (kp != null) return kp;
        String rp = edRProblem(sig); if (rp != null) return rp;
        return edVerify(pk, msg, sig) ? null : "bad_signature";
    }
    static Boolean mldsaSupported() { try { Signature.getInstance("ML-DSA-65"); return true; } catch (Exception e) { return false; } }
    static boolean mldsaVerify(byte[] pk, byte[] msg, byte[] sig) { try { Signature v = Signature.getInstance("ML-DSA-65"); v.initVerify(key("ML-DSA", MLDSA65_SPKI, pk)); v.update(msg); return v.verify(sig); } catch (Exception e) { return false; } }

    // \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 instants (same value profile as Python/JS/Go) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    static long[] parseInstant(String s) throws Bad {   // (epoch seconds, nanos) or Bad
        Matcher m = TS.matcher(s == null ? "" : s);
        if (!m.matches()) throw new Bad("timestamp outside the profile YYYY-MM-DDThh:mm:ss[.fraction](Z|\u00b1hh:mm)");
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

    // \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 receipt (minimal JSON writer) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    static String j(Object v) {
        if (v == null) return "null";
        if (v instanceof Boolean || v instanceof Integer || v instanceof Long) return String.valueOf(v);
        if (v instanceof String) { StringBuilder b = new StringBuilder(); writeString(b, (String) v); return b.toString(); }
        if (v instanceof List) { StringBuilder b = new StringBuilder("["); List<?> l = (List<?>) v; for (int k = 0; k < l.size(); k++) { if (k > 0) b.append(","); b.append(j(l.get(k))); } return b.append("]").toString(); }
        if (v instanceof Map) { StringBuilder b = new StringBuilder("{"); boolean first = true; for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) { if (!first) b.append(","); first = false; b.append(j(e.getKey())).append(":").append(j(e.getValue())); } return b.append("}").toString(); }
        return "\"?\"";
    }

    // \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 the verdict \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    public static void main(String[] args) {
        // stderr in UTF-8 on every system: on Windows the default is the code page, and "\u00b1" of a usage line reached a
        // UTF-8 reader as a byte it does not take (CI run 45377477990); the receipt itself is ASCII (j() escapes)
        System.setErr(new java.io.PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.err), true, StandardCharsets.UTF_8));
        try { run(args); }
        catch (Throwable t) {   // never a stack trace: a JSON FAIL receipt (r5: Path NUL bytes, OOM)
            emit("{\"verdict\":\"FAIL\",\"failures\":[\"internal: " + t.getClass().getSimpleName() + "\"],\"scope\":\"" + SCOPE.replace("\"", "'") + "\"}", 1);
        }
    }
    static void run(String[] args) throws Exception {
        String ledger = null, tip = "", tpk = "", tpq = "", nb = "", lid = "", epk = "", epq = ""; boolean reqTip = false, reqPQ = false;
        for (int k = 0; k < args.length; k++) {
            String a = args[k];
            try {
                switch (a) {
                    case "-tip": tip = once(tip, args, ++k); break; case "-trusted-pubkey": tpk = once(tpk, args, ++k); break; case "-trusted-pq-pubkey": tpq = once(tpq, args, ++k); break;
                    case "-tip-not-before": nb = once(nb, args, ++k); break; case "-expect-ledger-id": lid = once(lid, args, ++k); break; case "-pubkey": epk = once(epk, args, ++k); break;
                    case "-pq-pubkey": epq = once(epq, args, ++k); break; case "-require-tip": reqTip = true; break; case "-require-pq": reqPQ = true; break;
                    default: if (a.startsWith("-") || ledger != null) { usage(); return; } ledger = a;
                }
            } catch (ArrayIndexOutOfBoundsException e) { usage(); return; }
        }
        if (ledger == null) { usage(); return; }
        if (!lid.isEmpty() && !isHexN(lid, 64)) { usage(); return; }   // SPEC v0.9 \u00a717: a value that can match no ledger is a usage error
        Map<String, Object> out = verify(ledger, tip, tpk, tpq, epk, epq, reqPQ, reqTip, nb, lid);
        emit(j(out), "PASS".equals(out.get("verdict")) ? 0 : 1);
    }
    static final int EX_IOERR = 74;   // sysexits.h: the receipt could not be written whole (0.20.3)
    // The receipt goes to fd 1 through the FileChannel of a FileOutputStream, in a loop that sees the count: a failed write
    // is an IOException with its reason (System.out, a PrintStream, swallows it: 0.20.2 exited with the verdict's code on
    // a full disk or a closed stdout). On a stdout that is non-blocking and full (a reader that reads late) the channel
    // returns 0 instead of failing: the JDK's public API cannot poll fd 1, so a 0 is waited out in sleeps of 1 to 50 ms
    // (no spin) and retried, as a blocking write would wait; a reader that goes away makes the next write EPIPE: 74.
    // The receipt is ASCII (j() escapes everything outside 0x20..0x7e), ended by "\n" on every system (0.29.0; until then
    // System.lineSeparator(), "\r\n" on Windows).
    static void emit(String receipt, int code) {
        try {
            // "\n" on every system, as verifier.py since 0.29.0 (System.lineSeparator() wrote "\r\n" on Windows)
            java.nio.ByteBuffer b = java.nio.ByteBuffer.wrap((receipt + "\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            java.nio.channels.FileChannel fd1 = new java.io.FileOutputStream(java.io.FileDescriptor.out).getChannel();   // unbuffered: no flush to forget
            long nap = 1;
            while (b.hasRemaining()) {
                if (fd1.write(b) > 0) { nap = 1; continue; }
                Thread.sleep(nap);
                nap = Math.min(nap * 2, 50);
            }
        } catch (java.io.IOException | InterruptedException e) {
            System.err.println("receipt not written: " + java.util.Objects.toString(e.getMessage(), e.getClass().getSimpleName()));
            System.err.flush();
            System.exit(EX_IOERR);
        }
        System.exit(code);
    }
    // a value flag given with "" or with a flag as its value would silently mean "not given": usage (21/09/2026, one grammar in the five)
    // a value flag given twice: usage (the first value would be dropped: SPEC v0.9 \u00a717, NEMESIS 16/11/2026)
    static String once(String current, String[] args, int k) { if (!current.isEmpty()) usage(); return val(args, k); }
    static String val(String[] args, int k) { if (k >= args.length || args[k].isEmpty() || args[k].startsWith("-")) usage(); return args[k]; }
    static void usage() { System.err.println("usage: java CvVerify.java <ledger.jsonl> [-tip F] [-trusted-pubkey HEX] [-trusted-pq-pubkey B64] [-require-tip] [-tip-not-before ISO] [-expect-ledger-id HEX] [-pubkey HEX] [-pq-pubkey B64] [-require-pq]"); System.exit(2); }

    static Map<String, Object> verify(String ledgerPath, String tipPath, String tpk, String tpq, String epk, String epq, boolean reqPQ, boolean reqTip, String nb, String lid) throws Exception {
        Map<String, Object> v = new LinkedHashMap<>(); List<String> failures = new ArrayList<>();
        List<Obj> objects = new ArrayList<>();
        boolean hashOK = true, linkOK = true; String algo = ""; String prev = GENESIS, first = ""; int i = 0, line = 0;
        List<byte[]> lines = new ArrayList<>();
        try {
            // SPEC \u00a722 rule 8: a regular file or a FIFO of at most MAX_INPUT_BYTES (fail-closed on size, like verifier.py, r5),
            // a FIFO idle FIFO_IDLE_SECONDS at most (it waited without end until 2026-11-22), a directory or a device not read
            ByteArrayOutputStream cur = new ByteArrayOutputStream();
            long[] cnt = new long[3];   // SPEC \u00a722 rule 9: LF, tokens, last byte (0 none, 1 LF, 2 other); past a bound only counted
            readInput(Path.of(ledgerPath), MAX_INPUT_BYTES, true, (b, n) -> {
                for (int k = 0; k < n; k++) {
                    byte c = b[k];
                    if (c == '{' || c == '[' || c == ',' || c == ':') cnt[1]++;
                    cnt[2] = c == '\n' ? 1 : 2;
                    boolean keep = cnt[0] < MAX_INPUT_LINES && cnt[1] <= MAX_JSON_TOKENS;
                    if (c == '\n') { cnt[0]++; if (keep) lines.add(cur.toByteArray()); cur.reset(); } else if (keep) cur.write(c);
                }
            });
            long nLines = cnt[0] + (cnt[2] == 2 ? 1 : 0);
            if (nLines > MAX_INPUT_LINES) throw new InputRefused("input_too_large: more than " + MAX_INPUT_LINES + " lines");
            if (cnt[1] > MAX_JSON_TOKENS) throw new InputRefused("input_too_large: more than " + MAX_JSON_TOKENS + " JSON tokens");
            if (cur.size() > 0) lines.add(cur.toByteArray());
        } catch (InputRefused e) { v.put("verdict", "FAIL"); v.put("failures", List.of(e.getMessage())); v.put("scope", SCOPE); return v;
        } catch (IOException | RuntimeException e) { v.put("verdict", "FAIL"); v.put("failures", List.of("open: " + e.getClass().getSimpleName())); v.put("scope", SCOPE); return v; }
        for (byte[] raw : lines) {
            line++;
            if (isBlank(raw)) continue;   // blank = ASCII space/tab/CR only
            Object val;
            try { val = parse(raw); } catch (Bad e) { failures.add("line " + line + ": " + e.getMessage()); hashOK = false; objects.add(null); i++; continue; }
            if (!(val instanceof Obj)) { failures.add("line " + line + ": entry is not an object"); hashOK = false; objects.add(null); i++; continue; }
            Obj e = (Obj) val; objects.add(e);
            List<String> unk = unknownFields(e);   // SPEC \u00a72.1: closed entry schema \u2014 named, never silent (a LIST: the empty key "" is unknown too)
            if (!unk.isEmpty()) failures.add("entry " + i + ": unknown_field:" + joinCut(unk));
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
        // SPEC v0.9 \u00a717 rule 1 (16/11/2026): the ledger identity is entry 0's self_hash, readable without a tip, so the expected
        // identity is compared in every branch (until 0.25.0 only inside checkTip: without a tip another ledger was PASS)
        if (!lid.isEmpty() && (i == 0 || !lid.equals(first))) { v.put("verdict", "FAIL"); failures.add("ledger_id_mismatch: entry 0's self_hash is not the ledger id you expect (-expect-ledger-id)" + (i == 0 ? "; the file has no entry" : "")); }

        // per-entry signatures (same rules as signer.py / Go VerifyLedgerFull)
        if (reqPQ && epq.isEmpty()) { failures.add("require_pq_without_key: -require-pq needs -pq-pubkey (a post-quantum layer verified against the key inside the ledger is self-declared)"); v.put("verdict", "FAIL"); v.put("scope", SCOPE); return v; }
        if (!epq.isEmpty() && epk.isEmpty()) { failures.add("pq_key_without_ed25519_key: -pq-pubkey needs -pubkey (hybrid means both keys are pinned)"); v.put("verdict", "FAIL"); v.put("scope", SCOPE); return v; }
        // 0.21.0 (SPEC v0.4 \u00a75 step 5, signature profile): the layer is any of the four signature fields in any entry (until
        // 0.20.3 only "signature"), and a layer that does not verify is a FAIL with or without a key (until 0.20.3 only with -pubkey)
        boolean hasSig = false;
        for (Obj o : objects) if (o != null && (o.vals.containsKey("signature") || o.vals.containsKey("signer") || o.vals.containsKey("signature_pq") || o.vals.containsKey("signer_pq"))) { hasSig = true; break; }
        if (hasSig || !epk.isEmpty() || !epq.isEmpty()) {
            Map<String, Object> sc = signatures(objects, epk, epq, reqPQ);
            v.put("signatures", sc);
            Object pqp = sc.get("pq_protected");
            if ((!epk.isEmpty() || !epq.isEmpty()) && (!(Boolean) sc.get("ok") || (!epq.isEmpty() && !Boolean.TRUE.equals(pqp)))) {
                v.put("verdict", "FAIL"); failures.add("signatures_failed: the pinned signature layer does not verify (" + sc.get("pq_status") + ")");
            } else if (epk.isEmpty() && epq.isEmpty() && !(Boolean) sc.get("ok")) {
                v.put("verdict", "FAIL"); failures.add("signatures_failed: the signature layer the ledger carries does not verify (no key pinned)");
            }
        }
        // signed chain tip; SPEC v0.9 \u00a717 rule 2: the oldest acceptable tip makes the tip required (until 0.25.0: without a tip, PASS)
        if (!nb.isEmpty()) reqTip = true;
        if (!tpk.isEmpty()) reqTip = true;   // SPEC v0.14 \u00a722 rule 1: the trusted log key makes the tip required (until 0.27.0 without a tip: PASS)
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
    /** The entry's top-level keys outside ENTRY_KEYS, sorted by code point (Python sorted()). The oracle caught a first version that
     *  returned the joined string and tested it for emptiness: the empty key "" passed silently in Java and JS alone. */
    static List<String> unknownFields(Obj e) {
        List<String> unk = new ArrayList<>(); for (String k : e.keys) if (!ENTRY_KEYS.contains(k)) unk.add(k);
        unk.sort(BY_CODEPOINT); return unk;
    }
    /** joined by ",", cut to 120 code points as the reference's `[:120]` does */
    static String joinCut(List<String> unk) { String s = String.join(",", unk); return s.codePointCount(0, s.length()) > 120 ? s.substring(0, s.offsetByCodePoints(0, 120)) : s; }
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
            String why = edStrict(hex(signer), sh.getBytes(StandardCharsets.UTF_8), rawSig);   // 0.21.0: small/mixed order, named
            if (why == null) { verified++; signers.add(signer); } else fails.add("idx " + k + ": " + why);
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
        else if (pqPresent == 0) { prot = false; status = "absent"; note = "no post-quantum signatures (Ed25519 only: not quantum-resistant; NIST IR 8547 final, October 2026: EdDSA deprecated after 2030, disallowed after 2035)"; }
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

    // SPEC \u00a722 rule 2, rows 4-13: the first reason (without "tip_invalid: ") or null when every row holds
    static String tipShape(Obj t) {
        if (!TIP_KIND.equals(str(t, "kind"))) return "not a cryptovalid_tip/1 document";
        List<String> unk = new ArrayList<>();
        for (String k : t.keys) if (!TIP_MEMBERS.contains(k)) unk.add(k);
        if (!unk.isEmpty()) { unk.sort(BY_CODEPOINT); return "unknown_member:" + joinCut(unk); }
        for (String k : new String[]{"entries", "ledger_id", "tip_sha256", "ts", "signature_hex"}) if (!t.vals.containsKey(k)) return "tip missing field " + k;
        Object en = t.vals.get("entries"); long n = -1;
        if (en instanceof Num) { try { n = Long.parseLong(((Num) en).lexeme); } catch (NumberFormatException e) { n = -1; } }
        if (n < 0) return "tip entries must be a non-negative integer";
        String ledgerId = str(t, "ledger_id"), tipSha = str(t, "tip_sha256"), ts = str(t, "ts"), sigHex = str(t, "signature_hex");
        Object lpk = t.vals.get("log_pubkey_hex");
        if (ledgerId == null || tipSha == null || ts == null || sigHex == null || (lpk != null && !(lpk instanceof String))) return "tip fields must be strings";
        if (!isHexN(ledgerId, 64) || !isHexN(tipSha, 64)) return "ledger_id / tip_sha256 must be 64 lowercase hex characters";
        if (!isHexN(sigHex, 128)) return "signature_hex must be 128 lowercase hex characters";
        if (t.vals.containsKey("signature_pq_hex") || t.vals.containsKey("log_pq_pubkey_b64")) {
            String spq = str(t, "signature_pq_hex"), kpq = str(t, "log_pq_pubkey_b64");
            if (spq == null || !isHexN(spq, 6618)) return "signature_pq_hex must be 6618 lowercase hex characters (ML-DSA-65)";
            if (kpq == null || b64Strict(kpq, 1952) == null) return "log_pq_pubkey_b64 must be strict base64 of a 1952-byte ML-DSA-65 public key";
        }
        if (!plainTS(ts)) return "ts outside the profile YYYY-MM-DDThh:mm:ss[.fraction](Z|\u00b1hh:mm)";
        return null;
    }

    // SPEC \u00a722 rule 2, row 1: a FIFO, a device, a directory or a file larger than MAX_INPUT_BYTES is "cannot be read";
    // read by readInput (rule 8): a path swapped for a FIFO after its attributes were read is row 1 after
    // FIFO_IDLE_SECONDS, not a wait for a writer, and the read is bounded whatever the file has become
    static byte[] readTipFile(Path p) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        readInput(p, MAX_INPUT_BYTES, false, (b, n) -> out.write(b, 0, n));
        return out.toByteArray();
    }

    // SPEC \u00a722 rule 8 (\u00a75 step 0 of verifier.py: open_ledger_input). The JDK has no non-blocking open: the type is read
    // from the attributes of the path (unix:mode; where that view is absent only a regular file passes), then the path
    // is opened and read in a second thread, and this one stops waiting after FIFO_IDLE_SECONDS without a byte and
    // without the end (a FIFO with no writer, or a path swapped for a FIFO after its attributes were read). At most
    // `limit` bytes; each chunk goes to `sink` in the reading thread, before the caller sees the outcome.
    static final int FIFO_IDLE_SECONDS = 10;   // verifier.py FIFO_IDLE_SECONDS
    static final String INPUT_NOT_REGULAR = "unreadable: not a regular file";
    static final String INPUT_TOO_LARGE = "input_too_large: file exceeds " + MAX_INPUT_BYTES + " bytes";
    static final String INPUT_FIFO_IDLE = "unreadable: FIFO idle for " + FIFO_IDLE_SECONDS + " s";
    static final class InputRefused extends IOException { InputRefused(String why) { super(why); } }
    interface Sink { void write(byte[] b, int n) throws IOException; }

    /** a name that may be a Windows device: under \\.\, or a DOS device name (CON, NUL, COM1...), an extension or not */
    static boolean windowsDevice(String p) {
        String n = p.substring(p.lastIndexOf('\\') + 1);
        int dot = n.indexOf('.');
        return p.startsWith("\\\\.\\")
            || (dot < 0 ? n : n.substring(0, dot)).trim().matches("(?i)(CON|PRN|AUX|NUL|(COM|LPT)[0-9])");
    }

    /** 0 a regular file, 1 a FIFO, 2 anything else (a directory, a device, a socket) */
    static int inputKind(Path p) throws IOException {
        // Windows: a named pipe (\\.\pipe\name), its FIFO, is known by its name; reading its attributes would take one
        // of its instances (an open), and the read needs the one there is
        if (File.separatorChar == '\\' && p.toString().toLowerCase(java.util.Locale.ROOT).startsWith("\\\\.\\pipe\\")) return 1;
        Object mode;
        try { mode = Files.getAttribute(p, "unix:mode"); }
        catch (UnsupportedOperationException | IllegalArgumentException e) {
            try { return Files.readAttributes(p, java.nio.file.attribute.BasicFileAttributes.class).isRegularFile() ? 0 : 2; }
            catch (java.nio.file.NoSuchFileException | java.nio.file.AccessDeniedException x) { throw x; }
            catch (java.nio.file.FileSystemException x) {   // a device (\\.\NUL, NUL) has no attributes on Windows
                if (windowsDevice(p.toString())) return 2;
                throw x;
            }
        }
        int fmt = ((Integer) mode) & 0170000;
        return fmt == 0100000 ? 0 : fmt == 0010000 ? 1 : 2;
    }

    static void readInput(Path p, long limit, boolean fifoOK, Sink sink) throws IOException {
        int kind = inputKind(p);
        if (kind == 2 || (kind == 1 && !fifoOK)) throw new InputRefused(INPUT_NOT_REGULAR);
        if (kind == 0 && Files.size(p) > limit) throw new InputRefused(INPUT_TOO_LARGE);
        final long[] last = { System.nanoTime() };   // the last byte (or the start), under `done`
        final Object[] done = new Object[1];         // null while reading; then Boolean.TRUE or the Throwable
        Thread t = new Thread(() -> {
            Object outcome = Boolean.TRUE;
            try (InputStream in = Files.newInputStream(p)) {
                byte[] b = new byte[1 << 16]; long n = 0; int r;
                while ((r = in.read(b)) >= 0) {
                    synchronized (done) { last[0] = System.nanoTime(); }
                    n += r;
                    if (n > limit) throw new InputRefused(INPUT_TOO_LARGE);
                    sink.write(b, r);
                }
            } catch (Throwable e) { outcome = e; }
            synchronized (done) { done[0] = outcome; done.notifyAll(); }
        }, "cvverify-input");
        t.setDaemon(true);   // a reader still waiting does not keep the process alive
        t.start();
        final long idle = java.util.concurrent.TimeUnit.SECONDS.toNanos(FIFO_IDLE_SECONDS);
        Object outcome;
        synchronized (done) {
            while (done[0] == null) {
                long left = idle - (System.nanoTime() - last[0]);
                if (left <= 0) throw new InputRefused(INPUT_FIFO_IDLE);
                try { done.wait(Math.max(1, left / 1_000_000)); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new InterruptedIOException(); }
            }
            outcome = done[0];
        }
        if (outcome instanceof IOException) throw (IOException) outcome;
        if (outcome instanceof RuntimeException) throw (RuntimeException) outcome;
        if (outcome instanceof Error) throw (Error) outcome;
    }

    static Map<String, Object> checkTip(String path, int entries, String first, String last, String tpk, String tpq, String nb, String lid) {
        Map<String, Object> tc = new LinkedHashMap<>(); tc.put("ok", false); tc.put("checked", true); tc.put("trusted", false); tc.put("tip_path", path); tc.put("pq_protected", false);
        // SPEC \u00a722 rule 2: the table of the reasons of a tip, rows 1-15 in order, the same words as Python, JS and Go
        byte[] rawTip;
        try { rawTip = readTipFile(Path.of(path)); }   // row 1: a regular file of at most MAX_INPUT_BYTES, as Python's read_regular
        catch (Exception e) { tc.put("why", "tip_unreadable: the tip file cannot be read"); return tc; }
        Object parsed;
        try { if (countTokens(rawTip) > MAX_JSON_TOKENS) throw new Bad("json_too_many_tokens"); parsed = parse(rawTip); }   // SPEC \u00a722 rule 9
        catch (Bad | RuntimeException e) { tc.put("why", "tip_unreadable: not a JSON text of the profile of SPEC \u00a73"); return tc; }
        if (!(parsed instanceof Obj)) { tc.put("why", "tip_unreadable: not a JSON object"); return tc; }
        Obj t = (Obj) parsed;
        String shape = tipShape(t);
        if (shape != null) { tc.put("why", "tip_invalid: " + shape); return tc; }
        String ledgerId = str(t, "ledger_id"), tipSha = str(t, "tip_sha256"), ts = str(t, "ts"), sigHex = str(t, "signature_hex"), logPk = str(t, "log_pubkey_hex");
        long n = Long.parseLong(((Num) t.vals.get("entries")).lexeme);
        String spq = str(t, "signature_pq_hex"), kpq = str(t, "log_pq_pubkey_b64");
        if (logPk != null && !logPk.isEmpty() && !logPk.equals(tpk)) { tc.put("why", "tip_invalid: tip log key differs from the trusted log key"); return tc; }
        byte[] payload = ("{\"entries\":" + n + ",\"kind\":\"" + TIP_KIND + "\",\"ledger_id\":\"" + ledgerId + "\",\"tip_sha256\":\"" + tipSha + "\",\"ts\":\"" + ts + "\"}").getBytes(StandardCharsets.UTF_8);
        if (!isHexN(tpk, 64)) { tc.put("why", "tip_invalid: tip signature invalid"); return tc; }
        String tipWhy = edStrict(hex(tpk), payload, hex(sigHex));   // 0.21.0: small/mixed order, named
        if (tipWhy != null) { tc.put("why", "tip_invalid: tip signature invalid" + ("bad_signature".equals(tipWhy) ? "" : " (" + tipWhy + ")")); return tc; }
        tc.put("trusted", true);
        if (!lid.isEmpty() && !ledgerId.equals(lid)) { tc.put("why", "ledger_id_mismatch: the tip belongs to a different ledger than the one you expect"); return tc; }
        if (entries > 0 && !ledgerId.equals(first)) { tc.put("why", "tip_of_another_ledger: the tip's ledger_id is not this file's first self_hash"); return tc; }
        if (!nb.isEmpty()) {
            long[] nbT; try { nbT = parseInstant(nb); } catch (Bad e) { tc.put("why", "bad_not_before: -tip-not-before must be YYYY-MM-DDThh:mm:ss[.f](Z|\u00b1hh:mm)"); return tc; }
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
