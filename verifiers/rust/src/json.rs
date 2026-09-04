//! Minimal JSON parser + canonical encoder (std only). The canonical form is the
//! twin of Python's json.dumps ON THE ACCEPTANCE PROFILE (no floats, ints in +/-(2^53-1), no dup keys)(sort_keys=True, separators=(",",":"),
//! ensure_ascii=True), which is what CryptoValid's self_hash commits to.
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<Json>),
    // BTreeMap keeps keys ordered by Unicode scalar value — same order Python sorts by.
    Object(BTreeMap<String, Json>),
}

pub struct Parser {
    s: Vec<char>,
    i: usize,
}

impl Parser {
    pub fn parse(text: &str) -> Result<Json, String> {
        let mut p = Parser {
            s: text.chars().collect(),
            i: 0,
        };
        let v = p.value()?;
        p.ws();
        if p.i != p.s.len() {
            return Err("trailing data".into());
        }
        Ok(v)
    }
    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], ' ' | '\t' | '\n' | '\r') {
            self.i += 1;
        }
    }
    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        let c = *self.s.get(self.i).ok_or("eof")?;
        match c {
            '{' => self.object(),
            '[' => self.array(),
            '"' => Ok(Json::Str(self.string()?)),
            't' => {
                self.lit("true")?;
                Ok(Json::Bool(true))
            }
            'f' => {
                self.lit("false")?;
                Ok(Json::Bool(false))
            }
            'n' => {
                self.lit("null")?;
                Ok(Json::Null)
            }
            _ => self.number(),
        }
    }
    fn lit(&mut self, w: &str) -> Result<(), String> {
        for c in w.chars() {
            if self.s.get(self.i) != Some(&c) {
                return Err("literal".into());
            }
            self.i += 1;
        }
        Ok(())
    }
    fn expect(&mut self, c: char) -> Result<(), String> {
        if self.s.get(self.i) != Some(&c) {
            return Err(format!("expected {}", c));
        }
        self.i += 1;
        Ok(())
    }
    fn object(&mut self) -> Result<Json, String> {
        self.expect('{')?;
        let mut m = BTreeMap::new();
        self.ws();
        if self.s.get(self.i) == Some(&'}') {
            self.i += 1;
            return Ok(Json::Object(m));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            self.expect(':')?;
            if m.contains_key(&k) {
                return Err(format!("duplicate key {k:?}"));   // hash malleability guard
            }
            m.insert(k, self.value()?);
            self.ws();
            if self.s.get(self.i) == Some(&',') {
                self.i += 1;
                continue;
            }
            self.expect('}')?;
            return Ok(Json::Object(m));
        }
    }
    fn array(&mut self) -> Result<Json, String> {
        self.expect('[')?;
        let mut a = Vec::new();
        self.ws();
        if self.s.get(self.i) == Some(&']') {
            self.i += 1;
            return Ok(Json::Array(a));
        }
        loop {
            a.push(self.value()?);
            self.ws();
            if self.s.get(self.i) == Some(&',') {
                self.i += 1;
                continue;
            }
            self.expect(']')?;
            return Ok(Json::Array(a));
        }
    }
    fn string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut out = String::new();
        while self.i < self.s.len() {
            let c = self.s[self.i];
            self.i += 1;
            if c == '"' {
                return Ok(out);
            }
            if c == '\\' {
                let e = *self.s.get(self.i).ok_or("bad escape")?;
                self.i += 1;
                match e {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    'b' => out.push('\u{08}'),
                    'f' => out.push('\u{0C}'),
                    '/' => out.push('/'),
                    '\\' => out.push('\\'),
                    '"' => out.push('"'),
                    'u' => {
                        let hex: String = self.s[self.i..(self.i + 4).min(self.s.len())]
                            .iter()
                            .collect();
                        self.i += 4;
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| "bad \\u")?;
                        out.push(char::from_u32(code).ok_or("bad scalar")?);
                    }
                    _ => return Err("bad escape".into()),
                }
            } else {
                out.push(c);
            }
        }
        Err("unterminated string".into())
    }
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        while self.i < self.s.len() && "+-0123456789.eE".contains(self.s[self.i]) {
            self.i += 1;
        }
        let tok: String = self.s[start..self.i].iter().collect();
        if tok.is_empty() {
            return Err("bad number".into());
        }
        if tok.contains('.') || tok.contains('e') || tok.contains('E') {
            Err(format!("non-portable float {tok:?} (use a string)"))
        } else {
            let n: i64 = tok.parse().map_err(|_| "bad int".to_string())?;
            if n.unsigned_abs() > 9_007_199_254_740_991 {
                return Err(format!("integer {tok} outside portable range +/-(2^53-1)"));
            }
            Ok(Json::Int(n))
        }
    }
}

pub fn canonical(v: &Json) -> String {
    match v {
        Json::Null => "null".into(),
        Json::Bool(b) => {
            if *b {
                "true".into()
            } else {
                "false".into()
            }
        }
        Json::Int(n) => n.to_string(),
        Json::Float(f) => f.to_string(),
        Json::Str(s) => escape(s),
        Json::Array(a) => {
            let items: Vec<String> = a.iter().map(canonical).collect();
            format!("[{}]", items.join(","))
        }
        Json::Object(m) => {
            let items: Vec<String> = m
                .iter()
                .map(|(k, v)| format!("{}:{}", escape(k), canonical(v)))
                .collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

fn escape(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let cp = c as u32;
                if cp > 0xFFFF {
                    let v = cp - 0x10000;
                    out.push_str(&format!(
                        "\\u{:04x}\\u{:04x}",
                        0xD800 + (v >> 10),
                        0xDC00 + (v & 0x3FF)
                    ));
                } else {
                    out.push_str(&format!("\\u{:04x}", cp));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
