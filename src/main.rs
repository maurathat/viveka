//! The `viveka` command: keep and check a chain in a folder store.

use serde_json::Value;
use std::io::Read as _;
use std::process::ExitCode;
use viveka::{Address, Chain, FolderStore, Kind, ProposalState, Signer, Store};

const USAGE: &str = "\
viveka: a signed memory of what a system tried, and of the rule changes a person approved

  viveka keygen <keyfile>                       make a key; prints its public half
  viveka pubkey <keyfile>                       print a key's public half
  viveka init    -s <dir> -c <chain> -k <keyfile> -b <body.json>
                                                start a chain with a genesis record
  viveka add     -s <dir> -c <chain> -k <keyfile> -t <kind> -b <body.json>
                                                add a problem, proposal, decision,
                                                attempt or outcome; prints its address
  viveka verify  -s <dir> -c <chain>            check every record (SPEC.md, V1 to V9)
  viveka log     -s <dir> -c <chain>            list the records, oldest first
  viveka show    -s <dir> -c <chain> <address>  print one record
  viveka pending -s <dir> -c <chain>            list proposals and where each stands
  viveka rules   -s <dir> -c <chain> --at <n>   approved parameter values in force at
                                                round or epoch n

A body file of `-` reads the body from standard input. `--time <seconds>` sets a
record's time instead of the clock. Exit status: 0 done, 1 refused, 2 usage.";

struct Args {
    positional: Vec<String>,
    flags: std::collections::BTreeMap<String, String>,
}

fn parse_args(raw: &[String]) -> Result<Args, String> {
    let (mut positional, mut flags) = (Vec::new(), std::collections::BTreeMap::new());
    let mut it = raw.iter();
    while let Some(a) = it.next() {
        let name = match a.as_str() {
            "-s" | "--store" => "store",
            "-c" | "--chain" => "chain",
            "-k" | "--key" => "key",
            "-b" | "--body" => "body",
            "-t" | "--kind" => "kind",
            "--at" => "at",
            "--time" => "time",
            f if f.starts_with('-') && f != "-" => return Err(format!("unknown option {f}")),
            _ => {
                positional.push(a.clone());
                continue;
            }
        };
        let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
        flags.insert(name.to_string(), v.clone());
    }
    Ok(Args { positional, flags })
}

impl Args {
    fn need(&self, name: &str) -> Result<&str, String> {
        self.flags
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("missing --{name}"))
    }
    fn store(&self) -> Result<FolderStore, String> {
        Ok(FolderStore::new(self.need("store")?))
    }
    fn signer(&self) -> Result<Signer, String> {
        let path = self.need("key")?;
        let hex = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        Signer::from_hex(&hex).ok_or_else(|| format!("{path} does not hold a key"))
    }
    fn body(&self) -> Result<serde_json::Map<String, Value>, String> {
        let path = self.need("body")?;
        let bytes = if path == "-" {
            let mut b = Vec::new();
            std::io::stdin()
                .read_to_end(&mut b)
                .map_err(|e| e.to_string())?;
            b
        } else {
            std::fs::read(path).map_err(|e| format!("{path}: {e}"))?
        };
        match viveka::json::parse(&bytes).map_err(|e| e.to_string())? {
            Value::Object(o) => Ok(o),
            _ => Err("a body is a JSON object".into()),
        }
    }
    fn time(&self) -> Result<i64, String> {
        match self.flags.get("time") {
            Some(t) => t
                .parse()
                .map_err(|_| "--time takes whole seconds".to_string()),
            None => Ok(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)),
        }
    }
    fn load(&self) -> Result<(FolderStore, Chain), String> {
        let store = self.store()?;
        let chain = Chain::load(&store, self.need("chain")?).map_err(|e| e.to_string())?;
        Ok((store, chain))
    }
}

fn one_line(v: &Value, member: &str) -> String {
    v.get(member)
        .map(|x| {
            x.as_str()
                .map(str::to_string)
                .unwrap_or_else(|| x.to_string())
        })
        .unwrap_or_default()
}

fn run(cmd: &str, a: &Args) -> Result<(), String> {
    match cmd {
        "keygen" => {
            let path = a
                .positional
                .first()
                .ok_or("keygen needs a file to write the key to")?;
            if std::path::Path::new(path).exists() {
                return Err(format!("{path} already exists; a key is never overwritten"));
            }
            let s = Signer::generate().map_err(|e| e.to_string())?;
            write_secret(path, &s.to_hex())?;
            println!("{}", s.key());
        }
        "pubkey" => {
            let path = a.positional.first().ok_or("pubkey needs a key file")?;
            let hex = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            println!(
                "{}",
                Signer::from_hex(&hex)
                    .ok_or_else(|| format!("{path} does not hold a key"))?
                    .key()
            );
        }
        "init" => {
            let mut store = a.store()?;
            let chain = Chain::start(
                &mut store,
                &a.signer()?,
                a.need("chain")?,
                a.body()?,
                a.time()?,
            )
            .map_err(|e| e.to_string())?;
            println!("{}", chain.head());
        }
        "add" => {
            let kind = Kind::from_name(a.need("kind")?)
                .filter(|k| *k != Kind::Genesis)
                .ok_or("--kind is problem, proposal, decision, attempt or outcome")?;
            let (mut store, mut chain) = a.load()?;
            let address = chain
                .append(&mut store, &a.signer()?, kind, a.body()?, a.time()?)
                .map_err(|e| e.to_string())?;
            println!("{address}");
        }
        "verify" => {
            let (_, chain) = a.load()?;
            println!(
                "ok: {} records, head {}",
                chain.records().len(),
                chain.head()
            );
        }
        "log" => {
            let (_, chain) = a.load()?;
            for s in chain.records() {
                let body = Value::Object(s.record.body.clone());
                let about = match s.record.kind {
                    Kind::Genesis => one_line(&body, "purpose"),
                    Kind::Problem => one_line(&body, "title"),
                    Kind::Proposal => format!("{} ({})", body["change"], one_line(&body, "why")),
                    Kind::Decision => format!(
                        "{} {}",
                        one_line(&body, "verdict"),
                        one_line(&body, "proposal")
                    ),
                    Kind::Attempt => format!(
                        "rules {} by {}",
                        body["rules"],
                        one_line(&body["runner"], "name")
                    ),
                    Kind::Outcome => {
                        format!("observed {} over {} runs", body["observed"], body["runs"])
                    }
                };
                println!(
                    "{:>4}  {}  {:<8}  {}",
                    s.record.seq,
                    s.address,
                    s.record.kind.name(),
                    about
                );
            }
        }
        "show" => {
            let address = a
                .positional
                .first()
                .and_then(|s| Address::parse(s))
                .ok_or("show needs an address")?;
            let store = a.store()?;
            let bytes = store
                .get(a.need("chain")?, &address)
                .map_err(|e| e.to_string())?
                .ok_or("no such record in this chain")?;
            let signed = viveka::Signed::from_bytes(&bytes).map_err(|e| e.to_string())?;
            if signed.address != address {
                return Err(format!(
                    "breaks V2: the bytes stored under {address} have address {}",
                    signed.address
                ));
            }
            print!("{}", String::from_utf8_lossy(&bytes));
        }
        "pending" => {
            let (_, chain) = a.load()?;
            for (s, state) in chain.proposals() {
                let word = match state {
                    ProposalState::Pending => "pending",
                    ProposalState::Approved => "approved",
                    ProposalState::Rejected => "rejected",
                };
                println!(
                    "{word:<8}  {}  {}  {}",
                    s.address,
                    s.record.body["change"],
                    one_line(&Value::Object(s.record.body.clone()), "why")
                );
            }
        }
        "rules" => {
            let at: u64 = a
                .need("at")?
                .parse()
                .map_err(|_| "--at takes a round or epoch number")?;
            let (_, chain) = a.load()?;
            println!(
                "{}",
                serde_json::to_string(&chain.rules_at(at)).map_err(|e| e.to_string())?
            );
        }
        _ => return Err(format!("unknown command `{cmd}`")),
    }
    Ok(())
}

/// Write a secret key readable by its owner only.
fn write_secret(path: &str, hex: &str) -> Result<(), String> {
    use std::io::Write as _;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o.open(path).map_err(|e| format!("{path}: {e}"))?;
    writeln!(f, "{hex}").map_err(|e| format!("{path}: {e}"))
}

fn main() -> ExitCode {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = raw
        .first()
        .filter(|c| !matches!(c.as_str(), "-h" | "--help" | "help"))
    else {
        println!("{USAGE}");
        return ExitCode::from(if raw.is_empty() { 2 } else { 0 });
    };
    let args = match parse_args(&raw[1..]) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("viveka: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(cmd, &args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("viveka: {e}");
            ExitCode::from(1)
        }
    }
}
