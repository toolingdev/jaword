//! jaword: command-line client and MCP server for the jaword vault.
#![forbid(unsafe_code)]

mod mcp;
mod transfer;

use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "jaword", version, about = "Self-hosted secrets vault: CLI and MCP server")]
struct Cli {
    /// Vault address
    #[arg(long, env = "JAWORD_ADDR", default_value = "http://127.0.0.1:8200", global = true)]
    addr: String,
    /// Print raw JSON
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show whether the vault is initialized and sealed
    Status,
    /// Initialize a new vault (prompts for the unseal passphrase)
    Init,
    /// Unseal with the passphrase or recovery key (prompts)
    Unseal,
    /// Seal the vault (wipes keys from server memory)
    Seal,
    /// Change the unseal passphrase (prompts)
    Passphrase,
    /// Save an API token to ~/.config/jaword/token (prompts)
    Login,
    /// Remove the saved token
    Logout,
    /// Show the identity and permissions of the current token
    Whoami,
    /// List secrets
    Ls { prefix: Option<String> },
    /// Show metadata and version history
    Show { path: String },
    /// Create a secret; the vault generates the value unless --prompt/--stdin
    New {
        path: String,
        /// Friendly name shown in the UI, e.g. "Proxmox root"
        #[arg(long, default_value = "")]
        title: String,
        #[arg(long, default_value = "password")]
        kind: String,
        #[arg(long, default_value = "")]
        username: String,
        #[arg(long, default_value = "")]
        url: String,
        #[arg(long, default_value = "")]
        notes: String,
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Type the value at a hidden prompt
        #[arg(long)]
        prompt: bool,
        /// Read the value from stdin
        #[arg(long)]
        stdin: bool,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Payment cards: the number and security code are typed at a hidden prompt
    Card {
        #[command(subcommand)]
        cmd: CardCmd,
    },
    /// Gift cards: store them, record spending, see what is left
    Gift {
        #[command(subcommand)]
        cmd: GiftCmd,
    },
    /// People and addresses: yours, a relative's, home, work
    Person {
        #[command(subcommand)]
        cmd: PersonCmd,
    },
    /// Store a value you supply as a new version (hidden prompt or --stdin)
    Set {
        path: String,
        #[arg(long)]
        stdin: bool,
    },
    /// Edit metadata
    Edit {
        path: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// Replace all tags
        #[arg(long = "tag")]
        tags: Option<Vec<String>>,
    },
    /// Generate a new version inside the vault (value is not shown)
    Gen {
        path: String,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    /// Rotate: generate a new value and push it to the target system via the driver
    Rotate { path: String },
    /// After an interrupted rotation, promote or discard the pending version
    Resolve {
        path: String,
        #[arg(long, conflicts_with = "discard", required_unless_present = "discard")]
        promote: bool,
        #[arg(long)]
        discard: bool,
    },
    /// Print a secret value (humans only; refused for agent tokens)
    Reveal {
        path: String,
        #[arg(long)]
        version: Option<i64>,
    },
    /// Make an earlier version current again (when a new password did not take)
    Restore {
        path: String,
        #[arg(long)]
        version: i64,
    },
    /// Delete a secret (soft delete)
    Rm { path: String },
    /// Move or rename a secret, e.g. `jaword mv work/vpn business/vpn`
    Mv { path: String, new_path: String },
    /// Manage folders
    Folder {
        #[command(subcommand)]
        cmd: FolderCmd,
    },
    /// Run a command with secrets injected as environment variables
    Run {
        /// NAME=secret/path (repeatable)
        #[arg(short, long = "env", required = true)]
        env: Vec<String>,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Set or clear the rotation driver from a JSON file (admin)
    Driver {
        path: String,
        /// Driver JSON file; omit with --clear
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        clear: bool,
    },
    /// Import a CSV export from 1Password, Bitwarden, Chrome, Firefox, LastPass or KeePassXC
    Import {
        file: PathBuf,
        /// Folder to import into, e.g. `logins` gives logins/github-com
        #[arg(long, default_value = "imported")]
        prefix: String,
        /// Show what would be created without creating anything
        #[arg(long)]
        dry_run: bool,
        /// Delete the export file after a fully successful import
        #[arg(long)]
        remove_source: bool,
    },
    /// Export to a CSV or JSON file other password managers can import
    Export {
        /// Output file (created private, mode 0600)
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "csv")]
        format: String,
        #[arg(long, default_value = "")]
        prefix: String,
        /// Names, sites and usernames only, no secret values (works for agent tokens)
        #[arg(long)]
        metadata_only: bool,
    },
    /// Manage API tokens (admin)
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Show or verify the audit log (admin)
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: i64,
        /// Verify the tamper-evidence chain instead of listing
        #[arg(long)]
        verify: bool,
    },
    /// Check for or install a signed vault release
    Update {
        #[command(subcommand)]
        cmd: UpdateCmd,
    },
    /// Run as an MCP server on stdio (for AI agents)
    Mcp,
}

#[derive(Subcommand)]
enum CardCmd {
    /// Add a card, e.g. `jaword card new personal/cards/everyday --title "Everyday Visa" --exp 08/29`
    New {
        path: String,
        #[arg(long, default_value = "")]
        title: String,
        /// Name on the card
        #[arg(long, default_value = "")]
        holder: String,
        /// Expiry as MM/YY or MM/YYYY
        #[arg(long)]
        exp: Option<String>,
        /// Billing ZIP or postcode
        #[arg(long, default_value = "")]
        zip: String,
        #[arg(long, default_value = "")]
        notes: String,
    },
}

#[derive(clap::Args)]
struct PersonArgs {
    /// Full name
    #[arg(long)]
    name: Option<String>,
    #[arg(long)]
    email: Option<String>,
    #[arg(long)]
    phone: Option<String>,
    /// Date of birth as YYYY-MM-DD
    #[arg(long)]
    birthday: Option<String>,
    #[arg(long)]
    company: Option<String>,
    /// Street address
    #[arg(long)]
    line1: Option<String>,
    /// Apartment, suite, unit
    #[arg(long)]
    line2: Option<String>,
    #[arg(long)]
    city: Option<String>,
    /// State, province or region
    #[arg(long)]
    state: Option<String>,
    /// ZIP or postcode
    #[arg(long)]
    zip: Option<String>,
    #[arg(long)]
    country: Option<String>,
}

impl PersonArgs {
    /// Lay the given details over what is already stored.
    fn apply(&self, person: &mut Value) {
        let pairs = [
            ("full_name", &self.name), ("email", &self.email), ("phone", &self.phone), ("birthday", &self.birthday),
            ("company", &self.company), ("line1", &self.line1), ("line2", &self.line2), ("city", &self.city),
            ("region", &self.state), ("postal", &self.zip), ("country", &self.country),
        ];
        for (key, value) in pairs {
            if let Some(v) = value {
                person[key] = json!(v);
            }
        }
    }
}

#[derive(Subcommand)]
enum PersonCmd {
    /// Add a person or address, e.g. `jaword person new people/me-home --title "Me, home" --name "..." --line1 "..." --city ... --state CA --zip ...`
    New {
        path: String,
        /// What to call it, e.g. "Me, work" or a relative's name
        #[arg(long, default_value = "")]
        title: String,
        #[command(flatten)]
        details: PersonArgs,
        /// A number to keep sealed, typed at a hidden prompt. Repeat for more, e.g. --private Passport --private SSN
        #[arg(long = "private")]
        private: Vec<String>,
        #[arg(long, default_value = "")]
        notes: String,
    },
    /// Change details; anything you leave out is kept
    Edit {
        path: String,
        #[arg(long)]
        title: Option<String>,
        #[command(flatten)]
        details: PersonArgs,
    },
    /// List people and addresses with their details (never the sealed numbers)
    Ls,
}

#[derive(Subcommand)]
enum GiftCmd {
    /// Add a gift card, e.g. `jaword gift new personal/gift/bookshop --merchant Bookshop --balance 50`
    New {
        path: String,
        #[arg(long, default_value = "")]
        title: String,
        /// Store or brand the card is for
        #[arg(long, default_value = "")]
        merchant: String,
        /// Money on the card today, e.g. 50 or 37.20
        #[arg(long, default_value = "0")]
        balance: String,
        #[arg(long, default_value = "")]
        notes: String,
    },
    /// Record money spent, e.g. `jaword gift spend personal/gift/bookshop 12.34 --note "two paperbacks"`
    Spend {
        path: String,
        amount: String,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Record money added to the card
    Add {
        path: String,
        amount: String,
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Show what is left and the spending history
    Balance { path: String },
}

#[derive(Subcommand)]
enum FolderCmd {
    /// List folders with item counts
    Ls,
    /// Create an empty folder
    New { path: String },
    /// Rename or move a folder and everything in it
    Mv { from: String, to: String },
    /// Delete a folder. Deletes its items unless --move-to is given
    Rm {
        path: String,
        /// Move the items here instead of deleting them ("" = top level)
        #[arg(long)]
        move_to: Option<String>,
    },
}

#[derive(Subcommand)]
enum UpdateCmd {
    /// Show installed version and the result of the last check or install
    Status,
    /// Ask the vault to look up the latest release
    Check,
    /// Install a release, e.g. `jaword update apply v0.2.0`. Restarts and seals the vault
    Apply { version: String },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Create a token. Rules look like 'home-lab/**=list,generate,rotate'
    Create {
        name: String,
        #[arg(long, default_value = "agent")]
        role: String,
        #[arg(long = "rule")]
        rules: Vec<String>,
        #[arg(long)]
        ttl_days: Option<u32>,
    },
    Ls,
    Revoke { id: String },
}

#[derive(clap::Args, Default)]
struct PolicyArgs {
    /// Password length
    #[arg(long)]
    length: Option<usize>,
    /// Letters and digits only
    #[arg(long)]
    no_symbols: bool,
    /// Generate N random bytes as hex instead of a password
    #[arg(long, conflicts_with_all = ["length", "no_symbols", "base64"])]
    hex: Option<usize>,
    /// Generate N random bytes as base64url
    #[arg(long, conflicts_with_all = ["length", "no_symbols"])]
    base64: Option<usize>,
    /// Generate N random words (4-10) joined with dashes, e.g. Maple-Trumpet-Onion-Harbor-Cactus
    #[arg(long, conflicts_with_all = ["length", "no_symbols", "hex", "base64"])]
    words: Option<usize>,
}

impl PolicyArgs {
    fn to_json(&self) -> Option<Value> {
        if let Some(n) = self.hex {
            return Some(json!({"type": "hex", "bytes": n}));
        }
        if let Some(n) = self.base64 {
            return Some(json!({"type": "base64url", "bytes": n}));
        }
        if let Some(n) = self.words {
            return Some(json!({"type": "words", "words": n, "separator": "-", "capitalize": true}));
        }
        if self.length.is_none() && !self.no_symbols {
            return None;
        }
        let mut p = json!({"type": "password", "length": self.length.unwrap_or(32)});
        if self.no_symbols {
            p["symbols"] = json!("");
        }
        Some(p)
    }
}

// ------------------------------------------------------------------ client

pub struct Client {
    addr: String,
    token: Option<Zeroizing<String>>,
    agent: ureq::Agent,
}

pub struct ApiError {
    pub status: u16,
    pub message: String,
}

fn token_file() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))?;
    Some(base.join("jaword").join("token"))
}

const DEFAULT_ADDR: &str = "http://127.0.0.1:8200";

fn addr_file() -> Option<PathBuf> {
    token_file().map(|p| p.with_file_name("addr"))
}

/// Address precedence: --addr / JAWORD_ADDR, then the one saved by `login`.
fn resolve_addr(given: &str) -> String {
    if given != DEFAULT_ADDR {
        return given.to_string();
    }
    addr_file()
        .and_then(|f| std::fs::read_to_string(f).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| s.starts_with("http://") || s.starts_with("https://"))
        .unwrap_or_else(|| given.to_string())
}

fn load_token() -> Option<Zeroizing<String>> {
    if let Ok(t) = std::env::var("JAWORD_TOKEN") {
        if !t.trim().is_empty() {
            return Some(Zeroizing::new(t.trim().to_string()));
        }
    }
    let s = std::fs::read_to_string(token_file()?).ok()?;
    Some(Zeroizing::new(s.trim().to_string()))
}

fn urlencode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

impl Client {
    pub fn new(addr: &str) -> Client {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(330)))
            .max_redirects(0)
            .build()
            .into();
        let addr = addr.trim_end_matches('/').to_string();
        if addr.starts_with("http://") && !is_local(&addr) {
            eprintln!("warning: {addr} is plain HTTP to a non-local host; secrets would cross the network unencrypted");
        }
        Client { addr, token: load_token(), agent }
    }

    fn finish(&self, r: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Value, ApiError> {
        let mut resp = r.map_err(|e| ApiError { status: 0, message: format!("cannot reach vault at {}: {e}", self.addr) })?;
        let status = resp.status().as_u16();
        let body = resp.body_mut().read_to_string().unwrap_or_default();
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        if (200..300).contains(&status) {
            Ok(v)
        } else {
            let message = v["message"].as_str().map(str::to_string).unwrap_or_else(|| format!("HTTP {status}"));
            Err(ApiError { status, message })
        }
    }

    fn auth(&self) -> String {
        format!("Bearer {}", self.token.as_deref().map(String::as_str).unwrap_or(""))
    }

    pub fn get(&self, path_and_query: &str) -> Result<Value, ApiError> {
        let r = self.agent.get(format!("{}{}", self.addr, path_and_query)).header("Authorization", self.auth()).call();
        self.finish(r)
    }

    pub fn post(&self, path: &str, body: &Value) -> Result<Value, ApiError> {
        let text = Zeroizing::new(body.to_string());
        self.post_raw(path, &text)
    }

    pub fn post_raw(&self, path: &str, text: &str) -> Result<Value, ApiError> {
        let r = self
            .agent
            .post(format!("{}{}", self.addr, path))
            .header("Authorization", self.auth())
            .header("Content-Type", "application/json")
            .send(text);
        self.finish(r)
    }

    pub fn get_secret(&self, path: &str) -> Result<Value, ApiError> {
        self.get(&format!("/v1/secrets/get?path={}", urlencode(path)))
    }

    pub fn list(&self, prefix: &str) -> Result<Value, ApiError> {
        self.get(&format!("/v1/secrets?prefix={}", urlencode(prefix)))
    }
}

fn is_local(addr: &str) -> bool {
    let host = addr.trim_start_matches("http://");
    host.starts_with("127.") || host.starts_with("localhost") || host.starts_with("[::1]")
}

// ----------------------------------------------------------------- helpers

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn check(r: Result<Value, ApiError>) -> Value {
    match r {
        Ok(v) => v,
        Err(e) if e.status == 401 => die("not authenticated: run `jaword login` or set JAWORD_TOKEN"),
        Err(e) => die(&e.message),
    }
}

fn prompt_secret(label: &str) -> Zeroizing<String> {
    match rpassword::prompt_password(label) {
        Ok(s) => Zeroizing::new(s),
        Err(e) => die(&format!("cannot read input: {e}")),
    }
}

fn read_stdin_value() -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::new());
    if std::io::stdin().read_to_string(&mut s).is_err() {
        die("cannot read stdin");
    }
    // One trailing newline is an artifact of `echo`, not part of the secret.
    let trimmed = s.strip_suffix('\n').map(|t| t.strip_suffix('\r').unwrap_or(t)).unwrap_or(&s);
    Zeroizing::new(trimmed.to_string())
}

/// Unix seconds to `YYYY-MM-DD HH:MM` UTC (civil-from-days algorithm).
pub fn fmt_ts(ts: i64) -> String {
    let days = ts.div_euclid(86400);
    let secs = ts.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}Z", secs / 3600, (secs % 3600) / 60)
}

/// "12.34", "12", "$12.3" -> cents. Refuses anything it would have to guess at.
fn parse_money(text: &str) -> i64 {
    let t = text.trim().trim_start_matches('$').replace(',', "");
    let (whole, frac) = t.split_once('.').unwrap_or((&t, ""));
    let ok = !whole.is_empty()
        && whole.len() <= 8
        && frac.len() <= 2
        && whole.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit());
    if !ok {
        die("amount must look like 12.34");
    }
    let cents = whole.parse::<i64>().unwrap_or(0) * 100 + format!("{frac:0<2}").parse::<i64>().unwrap_or(0);
    if cents == 0 {
        die("amount must be more than zero");
    }
    cents
}

fn money(cents: i64) -> String {
    format!("{}${}.{:02}", if cents < 0 { "-" } else { "" }, cents.abs() / 100, cents.abs() % 100)
}

/// MM/YY or MM/YYYY -> (month, four-digit year).
fn parse_expiry(text: &str) -> (u8, u16) {
    let parsed = text.split_once('/').and_then(|(m, y)| {
        let m: u8 = m.trim().parse().ok()?;
        let y: u16 = y.trim().parse().ok()?;
        Some((m, if y < 100 { 2000 + y } else { y }))
    });
    match parsed {
        Some((m, y)) if (1..=12).contains(&m) => (m, y),
        _ => die("expiry must look like 08/29"),
    }
}

/// Short description of a card for listings: never more than the last four.
fn card_label(v: &Value) -> String {
    let c = &v["meta"]["card"];
    let g = &v["meta"]["gift"];
    if c.is_object() {
        let exp = match (c["exp_month"].as_u64().unwrap_or(0), c["exp_year"].as_u64().unwrap_or(0)) {
            (0, _) | (_, 0) => String::new(),
            (m, y) => format!("  exp {m:02}/{:02}", y % 100),
        };
        format!("{} ending {}{exp}", s(&c["brand"]), s(&c["last4"]))
    } else if g.is_object() {
        let left = v["balance_cents"].as_i64().unwrap_or(0);
        format!("{} ending {}  {} left", s(&g["merchant"]), s(&g["last4"]), money(left)).trim_start().to_string()
    } else {
        String::new()
    }
}

/// One-line summary of a person or address for listings.
fn person_label(v: &Value) -> String {
    let p = &v["meta"]["person"];
    if !p.is_object() {
        return String::new();
    }
    let place = [s(&p["city"]), s(&p["region"])].iter().filter(|x| !x.is_empty()).cloned().collect::<Vec<_>>().join(" ");
    [s(&p["full_name"]), s(&p["line1"]), place.as_str()].iter().filter(|x| !x.is_empty()).cloned().collect::<Vec<_>>().join(", ")
}

fn print_person(v: &Value) {
    let p = &v["meta"]["person"];
    let rows = [
        ("name", "full_name"), ("email", "email"), ("phone", "phone"), ("birthday", "birthday"), ("company", "company"),
        ("address", "line1"), ("", "line2"), ("city", "city"), ("state", "region"), ("zip", "postal"), ("country", "country"),
    ];
    for (label, key) in rows {
        if !s(&p[key]).is_empty() {
            println!("{:<9} {}", if label.is_empty() { String::new() } else { format!("{label}:") }, s(&p[key]));
        }
    }
    let sealed: Vec<&str> = p["sealed"].as_array().into_iter().flatten().map(s).collect();
    if !sealed.is_empty() {
        println!("sealed:   {} (use `jaword reveal`)", sealed.join(", "));
    }
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn print_secret_line(v: &Value) {
    let flags = format!(
        "{}{}",
        if v["has_driver"].as_bool().unwrap_or(false) { "R" } else { "-" },
        if v["pending_rotation"].as_bool().unwrap_or(false) { "P" } else { "-" }
    );
    println!(
        "{:<44} {:<9} v{:<3} {}  {}  {}",
        s(&v["path"]),
        s(&v["kind"]),
        v["current_version"],
        flags,
        fmt_ts(v["updated_at"].as_i64().unwrap_or(0)),
        if v["meta"]["person"].is_object() { person_label(v) } else if v["meta"]["card"].is_object() || v["meta"]["gift"].is_object() { card_label(v) } else { s(&v["meta"]["username"]).to_string() }
    );
}

fn parse_rule(r: &str) -> Value {
    let (path, caps) = r.split_once('=').unwrap_or_else(|| die("rule must look like 'home-lab/**=list,rotate'"));
    let caps: Vec<&str> = caps.split(',').map(str::trim).filter(|c| !c.is_empty()).collect();
    json!({"path": path, "caps": caps})
}

fn main() {
    let cli = Cli::parse();
    let c = Client::new(&resolve_addr(&cli.addr));
    let raw = cli.json;
    let out = |v: &Value| println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());

    match cli.cmd {
        Cmd::Mcp => mcp::serve(&c),
        Cmd::Status => {
            let v = check(c.get("/v1/sys/status"));
            if raw {
                out(&v)
            } else {
                println!("initialized: {}\nsealed:      {}\nserver:      {}", v["initialized"], v["sealed"], s(&v["version"]));
            }
        }
        Cmd::Init => {
            let st = check(c.get("/v1/sys/status"));
            if st["initialized"].as_bool().unwrap_or(false) {
                die("vault is already initialized");
            }
            println!("Choose the unseal passphrase (min 14 characters). It protects every secret in the vault.");
            let p1 = prompt_secret("Passphrase: ");
            let p2 = prompt_secret("Repeat:     ");
            if *p1 != *p2 {
                die("passphrases do not match");
            }
            let v = check(c.post("/v1/sys/init", &json!({"passphrase": p1.as_str()})));
            println!("\nVault initialized and unsealed.\n");
            println!("RECOVERY KEY (shown once; unseals the vault if the passphrase is lost):\n  {}\n", s(&v["recovery_key"]));
            println!("ROOT ADMIN TOKEN (shown once):\n  {}\n", s(&v["root_token"]));
            println!("Store both in your personal password manager now, then run `jaword login`.");
        }
        Cmd::Unseal => {
            let p = prompt_secret("Passphrase or recovery key: ");
            check(c.post("/v1/sys/unseal", &json!({"credential": p.as_str()})));
            println!("unsealed");
        }
        Cmd::Seal => {
            check(c.post("/v1/sys/seal", &json!({})));
            println!("sealed");
        }
        Cmd::Passphrase => {
            let cur = prompt_secret("Current passphrase: ");
            let p1 = prompt_secret("New passphrase:     ");
            let p2 = prompt_secret("Repeat:             ");
            if *p1 != *p2 {
                die("passphrases do not match");
            }
            check(c.post("/v1/sys/passphrase", &json!({"current": cur.as_str(), "new": p1.as_str()})));
            println!("passphrase changed");
        }
        Cmd::Login => {
            let t = prompt_secret("API token: ");
            let probe = Client { addr: c.addr.clone(), token: Some(Zeroizing::new(t.trim().to_string())), agent: c.agent.clone() };
            let who = check(probe.get("/v1/whoami"));
            let f = token_file().unwrap_or_else(|| die("cannot determine config directory"));
            if let Some(dir) = f.parent() {
                std::fs::create_dir_all(dir).unwrap_or_else(|e| die(&format!("{e}")));
            }
            write_private(&f, t.trim().as_bytes());
            write_private(&f.with_file_name("addr"), c.addr.as_bytes());
            println!("logged in to {} as {} ({}); saved under {}", c.addr, s(&who["name"]), s(&who["role"]), f.parent().map(|d| d.display().to_string()).unwrap_or_default());
            if s(&who["role"]) == "admin" {
                println!("note: an admin token on disk can be read by anything running as you, including AI agents.\n      Prefer the web UI for admin work and keep only a scoped token here; `jaword logout` removes it.");
            }
        }
        Cmd::Logout => {
            if let Some(f) = token_file() {
                let _ = std::fs::remove_file(f);
            }
            // The saved address is kept so the next `login` needs no --addr.
            println!("token removed");
        }
        Cmd::Whoami => out(&check(c.get("/v1/whoami"))),
        Cmd::Ls { prefix } => {
            let v = check(c.list(prefix.as_deref().unwrap_or("")));
            if raw {
                out(&v)
            } else {
                for x in v.as_array().into_iter().flatten() {
                    print_secret_line(x);
                }
            }
        }
        Cmd::Show { path } => {
            let v = check(c.get_secret(&path));
            if raw {
                out(&v)
            } else {
                if !s(&v["meta"]["title"]).is_empty() {
                    println!("name:     {}", s(&v["meta"]["title"]));
                }
                println!("path:     {}\nkind:     {}\nusername: {}\nurl:      {}\ntags:     {}", s(&v["path"]), s(&v["kind"]), s(&v["meta"]["username"]), s(&v["meta"]["url"]), v["meta"]["tags"]);
                if !s(&v["meta"]["notes"]).is_empty() {
                    println!("notes:    {}", s(&v["meta"]["notes"]));
                }
                if !card_label(&v).is_empty() {
                    println!("card:     {}", card_label(&v));
                }
                print_person(&v);
                println!("driver:   {}", if v["has_driver"].as_bool().unwrap_or(false) { "configured" } else { "none" });
                println!("\nversion  state     created            by");
                for x in v["versions"].as_array().into_iter().flatten() {
                    println!("{:<8} {:<9} {}  {}", x["version"], s(&x["state"]), fmt_ts(x["created_at"].as_i64().unwrap_or(0)), s(&x["created_by"]));
                }
            }
        }
        Cmd::New { path, title, kind, username, url, notes, tags, prompt, stdin, policy } => {
            let mut body = json!({"path": path, "kind": kind, "meta": {"title": title, "username": username, "url": url, "notes": notes, "tags": tags}});
            if let Some(p) = policy.to_json() {
                body["policy"] = p;
            }
            let value = if stdin {
                Some(read_stdin_value())
            } else if prompt {
                Some(prompt_secret("Value: "))
            } else {
                None
            };
            if let Some(v) = &value {
                body["value"] = json!(v.as_str());
            }
            let v = check(c.post("/v1/secrets/create", &body));
            println!("created {} (v{}){}", s(&v["path"]), v["current_version"], if value.is_none() { ", value generated in vault" } else { "" });
        }
        Cmd::Card { cmd: CardCmd::New { path, title, holder, exp, zip, notes } } => {
            let (exp_month, exp_year) = exp.as_deref().map(parse_expiry).unwrap_or((0, 0));
            let number = Zeroizing::new(prompt_secret("Card number: ").replace([' ', '-'], ""));
            let cvv = Zeroizing::new(prompt_secret("Security code (Enter to skip): ").trim().to_string());
            let value = Zeroizing::new(json!({"number": number.as_str(), "cvv": cvv.as_str()}).to_string());
            let body = json!({"path": path, "kind": "card", "value": value.as_str(), "meta": {
                "title": title, "notes": notes,
                "card": {"exp_month": exp_month, "exp_year": exp_year, "holder": holder, "zip": zip}}});
            let v = check(c.post("/v1/secrets/create", &body));
            println!("saved {}: {}", s(&v["path"]), card_label(&v));
        }
        Cmd::Person { cmd } => match cmd {
            PersonCmd::New { path, title, details, private, notes } => {
                let mut person = json!({});
                details.apply(&mut person);
                let mut body = json!({"path": path, "kind": "identity", "meta": {"title": title, "notes": notes, "person": person}});
                if !private.is_empty() {
                    let mut sealed = serde_json::Map::new();
                    for label in &private {
                        let number = prompt_secret(&format!("{label}: "));
                        sealed.insert(label.clone(), json!(number.trim()));
                    }
                    body["value"] = json!(Value::Object(sealed).to_string());
                }
                let v = check(c.post("/v1/secrets/create", &body));
                println!("saved {}: {}", s(&v["path"]), person_label(&v));
            }
            PersonCmd::Edit { path, title, details } => {
                let mut meta = check(c.get_secret(&path))["meta"].clone();
                if !meta["person"].is_object() {
                    die("that item is not a person or address");
                }
                if let Some(t) = title {
                    meta["title"] = json!(t);
                }
                details.apply(&mut meta["person"]);
                let v = check(c.post("/v1/secrets/update", &json!({"path": path, "meta": meta})));
                println!("saved {}: {}", s(&v["path"]), person_label(&v));
            }
            PersonCmd::Ls => {
                let all = check(c.list(""));
                let people: Vec<&Value> = all.as_array().into_iter().flatten().filter(|x| s(&x["kind"]) == "identity").collect();
                if raw {
                    out(&json!(people));
                } else {
                    for v in people {
                        println!("{}  ({})", if s(&v["meta"]["title"]).is_empty() { s(&v["path"]) } else { s(&v["meta"]["title"]) }, s(&v["path"]));
                        print_person(v);
                        println!();
                    }
                }
            }
        },
        Cmd::Gift { cmd } => match cmd {
            GiftCmd::New { path, title, merchant, balance, notes } => {
                let initial = if balance.trim() == "0" { 0 } else { parse_money(&balance) };
                let number = Zeroizing::new(prompt_secret("Gift card number: ").replace(' ', ""));
                let pin = Zeroizing::new(prompt_secret("PIN (Enter to skip): ").trim().to_string());
                let value = Zeroizing::new(json!({"number": number.as_str(), "pin": pin.as_str()}).to_string());
                let body = json!({"path": path, "kind": "gift_card", "value": value.as_str(), "meta": {
                    "title": title, "notes": notes, "gift": {"merchant": merchant, "initial_cents": initial}}});
                let v = check(c.post("/v1/secrets/create", &body));
                println!("saved {}: {}", s(&v["path"]), card_label(&v));
            }
            GiftCmd::Spend { path, amount, note } => {
                let v = check(c.post("/v1/secrets/ledger", &json!({"path": path, "cents": -parse_money(&amount), "note": note})));
                println!("recorded; {} left on {path}", money(v["balance_cents"].as_i64().unwrap_or(0)));
            }
            GiftCmd::Add { path, amount, note } => {
                let v = check(c.post("/v1/secrets/ledger", &json!({"path": path, "cents": parse_money(&amount), "note": note})));
                println!("recorded; {} left on {path}", money(v["balance_cents"].as_i64().unwrap_or(0)));
            }
            GiftCmd::Balance { path } => {
                let v = check(c.get_secret(&path));
                if raw {
                    out(&json!({"path": v["path"], "balance_cents": v["balance_cents"], "gift": v["meta"]["gift"]}));
                } else if !v["meta"]["gift"].is_object() {
                    die("that item is not a gift card");
                } else {
                    println!("{}", card_label(&v));
                    println!("started with {}", money(v["meta"]["gift"]["initial_cents"].as_i64().unwrap_or(0)));
                    for e in v["meta"]["gift"]["ledger"].as_array().into_iter().flatten() {
                        println!("{}  {:>10}  {}  ({})", fmt_ts(e["at"].as_i64().unwrap_or(0)), money(e["cents"].as_i64().unwrap_or(0)), s(&e["note"]), s(&e["by"]));
                    }
                }
            }
        },
        Cmd::Set { path, stdin } => {
            let value = if stdin { read_stdin_value() } else { prompt_secret("New value: ") };
            let v = check(c.post("/v1/secrets/update", &json!({"path": path, "value": value.as_str()})));
            println!("stored {} v{}", s(&v["path"]), v["current_version"]);
        }
        Cmd::Edit { path, title, username, url, notes, tags } => {
            let cur = check(c.get_secret(&path));
            let mut meta = cur["meta"].clone();
            if let Some(x) = title {
                meta["title"] = json!(x);
            }
            if let Some(x) = username {
                meta["username"] = json!(x);
            }
            if let Some(x) = url {
                meta["url"] = json!(x);
            }
            if let Some(x) = notes {
                meta["notes"] = json!(x);
            }
            if let Some(x) = tags {
                meta["tags"] = json!(x);
            }
            check(c.post("/v1/secrets/update", &json!({"path": path, "meta": meta})));
            println!("updated {path}");
        }
        Cmd::Gen { path, policy } => {
            let mut body = json!({"path": path});
            if let Some(p) = policy.to_json() {
                body["policy"] = p;
            }
            let v = check(c.post("/v1/secrets/generate", &body));
            println!("generated {} v{} (value not shown)", s(&v["path"]), v["current_version"]);
        }
        Cmd::Rotate { path } => {
            let v = check(c.post("/v1/secrets/rotate", &json!({"path": path})));
            if raw {
                out(&v);
            }
            if v["rotated"].as_bool().unwrap_or(false) {
                println!("rotated {} -> v{}", path, v["version"]);
            } else {
                die(&format!("rotation failed, previous value still current: {}", s(&v["error"])));
            }
        }
        Cmd::Resolve { path, promote, discard: _ } => {
            check(c.post("/v1/secrets/resolve", &json!({"path": path, "promote": promote})));
            println!("{}", if promote { "pending version promoted to current" } else { "pending version discarded" });
        }
        Cmd::Reveal { path, version } => {
            let v = check(c.post("/v1/secrets/reveal", &json!({"path": path, "version": version})));
            let mut o = std::io::stdout();
            let _ = o.write_all(s(&v["value"]).as_bytes());
            if o.is_terminal() {
                let _ = o.write_all(b"\n");
            }
        }
        Cmd::Restore { path, version } => {
            let v = check(c.post("/v1/secrets/restore", &json!({"path": path, "version": version})));
            println!("restored version {version} of {path} as v{}", v["current_version"]);
        }
        Cmd::Rm { path } => {
            check(c.post("/v1/secrets/delete", &json!({"path": path})));
            println!("deleted {path}");
        }
        Cmd::Run { env, command } => {
            let mut cmd = std::process::Command::new(&command[0]);
            cmd.args(&command[1..]);
            for e in &env {
                let (name, path) = e.split_once('=').unwrap_or_else(|| die("--env must be NAME=secret/path"));
                let v = check(c.post("/v1/secrets/reveal", &json!({"path": path})));
                cmd.env(name, s(&v["value"]));
            }
            cmd.env_remove("JAWORD_TOKEN");
            match cmd.status() {
                Ok(st) => std::process::exit(st.code().unwrap_or(1)),
                Err(e) => die(&format!("cannot run {}: {e}", command[0])),
            }
        }
        Cmd::Driver { path, file, clear } => {
            let driver = match (file, clear) {
                (Some(f), false) => {
                    let text = std::fs::read_to_string(&f).unwrap_or_else(|e| die(&format!("{}: {e}", f.display())));
                    serde_json::from_str::<Value>(&text).unwrap_or_else(|e| die(&format!("invalid JSON: {e}")))
                }
                (None, true) => Value::Null,
                _ => die("give exactly one of --file or --clear"),
            };
            check(c.post("/v1/secrets/driver", &json!({"path": path, "driver": driver})));
            println!("driver {} for {path}", if clear { "cleared" } else { "saved" });
        }
        Cmd::Import { file, prefix, dry_run, remove_source } => {
            match transfer::import_file(&c, &transfer::ImportOpts { file, prefix, dry_run, remove_source }) {
                Ok(v) => out(&v),
                Err(e) => die(&e),
            }
        }
        Cmd::Export { out: file, format, prefix, metadata_only } => match transfer::export(&c, &file, &format, &prefix, metadata_only) {
            Ok(v) => out(&v),
            Err(e) => die(&e),
        },
        Cmd::Mv { path, new_path } => {
            check(c.post("/v1/secrets/move", &json!({"path": path, "new_path": new_path})));
            println!("moved {path} -> {new_path}");
        }
        Cmd::Folder { cmd } => match cmd {
            FolderCmd::Ls => {
                let v = check(c.get("/v1/folders"));
                if raw {
                    out(&v)
                } else {
                    for f in v.as_array().into_iter().flatten() {
                        println!("{:<50} {}", s(&f["path"]), f["count"]);
                    }
                }
            }
            FolderCmd::New { path } => {
                check(c.post("/v1/folders/create", &json!({"path": path})));
                println!("created folder {path}");
            }
            FolderCmd::Mv { from, to } => {
                let v = check(c.post("/v1/folders/move", &json!({"from": from, "to": to})));
                println!("moved {from} -> {to} ({} items)", v["moved"]);
            }
            FolderCmd::Rm { path, move_to } => {
                let mut body = json!({"path": path});
                if let Some(m) = &move_to {
                    body["move_to"] = json!(m);
                }
                let v = check(c.post("/v1/folders/delete", &body));
                println!("deleted folder {path}; {} items {}", v["items"], if move_to.is_some() { "moved" } else { "deleted" });
            }
        },
        Cmd::Update { cmd } => {
            let v = match cmd {
                UpdateCmd::Status => check(c.get("/v1/sys/update")),
                UpdateCmd::Check => {
                    check(c.post("/v1/sys/update", &json!({"action": "check"})));
                    std::thread::sleep(Duration::from_secs(4));
                    check(c.get("/v1/sys/update"))
                }
                UpdateCmd::Apply { version } => {
                    check(c.post("/v1/sys/update", &json!({"action": "apply", "version": version})));
                    println!("install requested; the vault will restart and must then be unsealed");
                    json!({"requested": version})
                }
            };
            out(&v);
        }
        Cmd::Token { cmd } => match cmd {
            TokenCmd::Create { name, role, rules, ttl_days } => {
                let rules: Vec<Value> = rules.iter().map(|r| parse_rule(r)).collect();
                let v = check(c.post("/v1/tokens/create", &json!({"name": name, "role": role, "rules": rules, "ttl_days": ttl_days})));
                println!("token id: {}\ntoken (shown once):\n  {}", s(&v["id"]), s(&v["token"]));
            }
            TokenCmd::Ls => {
                let v = check(c.get("/v1/tokens"));
                if raw {
                    out(&v)
                } else {
                    for t in v.as_array().into_iter().flatten() {
                        let state = if !t["revoked_at"].is_null() { "revoked" } else { "active" };
                        println!("{}  {:<20} {:<6} {:<8} last used {}", s(&t["id"]), s(&t["name"]), s(&t["role"]), state, t["last_used_at"].as_i64().map(fmt_ts).unwrap_or_else(|| "never".into()));
                    }
                }
            }
            TokenCmd::Revoke { id } => {
                check(c.post("/v1/tokens/revoke", &json!({"id": id})));
                println!("revoked {id}");
            }
        },
        Cmd::Audit { limit, verify } => {
            if verify {
                let v = check(c.get("/v1/audit/verify"));
                if v["intact"].as_bool().unwrap_or(false) {
                    println!("audit chain intact ({} rows)", v["rows"]);
                } else {
                    die(&format!("AUDIT CHAIN BROKEN at seq {}", v["first_bad_seq"]));
                }
            } else {
                let v = check(c.get(&format!("/v1/audit?limit={limit}")));
                if raw {
                    out(&v)
                } else {
                    for r in v.as_array().into_iter().flatten().collect::<Vec<_>>().into_iter().rev() {
                        println!("{:>6}  {}  {:<28} {:<16} {:<9} {} {}", r["seq"], fmt_ts(r["ts"].as_i64().unwrap_or(0)), s(&r["actor"]), s(&r["action"]), s(&r["outcome"]), s(&r["path"]), s(&r["detail"]));
                    }
                }
            }
        }
    }
}

pub(crate) fn write_private(path: &std::path::Path, data: &[u8]) {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).unwrap_or_else(|e| die(&format!("{}: {e}", path.display())));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    f.write_all(data).unwrap_or_else(|e| die(&format!("{e}")));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(fmt_ts(0), "1970-01-01 00:00Z");
        assert_eq!(fmt_ts(1_700_000_000), "2023-11-14 22:13Z");
        assert_eq!(fmt_ts(951_782_400), "2000-02-29 00:00Z");
    }

    #[test]
    fn url_encoding() {
        assert_eq!(urlencode("infra/pve/root"), "infra/pve/root");
        assert_eq!(parse_money("12.34"), 1234);
        assert_eq!(parse_money("$1,250"), 125000);
        assert_eq!(parse_money("0.5"), 50);
        assert_eq!(money(-1234), "-$12.34");
        assert_eq!(parse_expiry("08/29"), (8, 2029));
        assert_eq!(parse_expiry("12/2031"), (12, 2031));
        let card = json!({"meta": {"card": {"brand": "Visa", "last4": "1111", "exp_month": 8, "exp_year": 2029}}});
        assert_eq!(card_label(&card), "Visa ending 1111  exp 08/29");
        let who = json!({"meta": {"person": {"full_name": "Test Person", "line1": "1 Example Street", "city": "Springfield", "region": "CA"}}});
        assert_eq!(person_label(&who), "Test Person, 1 Example Street, Springfield CA");
        let gift = json!({"balance_cents": 3766, "meta": {"gift": {"merchant": "Bookshop", "last4": "XYZ9"}}});
        assert_eq!(card_label(&gift), "Bookshop ending XYZ9  $37.66 left");
        assert_eq!(urlencode("a b&c=d#e"), "a%20b%26c%3Dd%23e");
    }
}
