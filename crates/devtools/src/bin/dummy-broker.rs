//! Dev observer: subscribes to the agent's NATS channels and pretty-prints
//! every envelope — the Rust replacement of legacy `DummyBroker`.
//!
//! Unlike the legacy tool this does not bundle a broker by default: point it
//! at a running nats-server with `--uri`, or hand it a `nats-server.exe`
//! path to spawn for the session with `--spawn` (killed on exit).
//!
//! Every message is parsed as a protocol v3 envelope; anything that fails to
//! parse is printed raw and counted as `unparsed` — a dev tool must survive
//! and expose hostile traffic, not choke on it. Sequence numbers are tracked
//! per channel: gaps mean dropped messages (broker restart, publisher loss),
//! regressions mean a second publisher or an agent restart on the same
//! subject. Ctrl+C prints a per-type summary and exits.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::Duration,
};

use futures_util::StreamExt;
use protocol::nats::Envelope;

/// Connection retry budget for the dev harness (impatient on purpose).
const CONNECT_ATTEMPTS: u32 = 10;

/// Which agent channel a message arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Channel {
    /// Keepalive / reboot / shutdown.
    Control,
    /// Behavioral telemetry and reports.
    Events,
}

impl Channel {
    fn label(self) -> &'static str {
        match self {
            Channel::Control => "control",
            Channel::Events => "events",
        }
    }
}

/// Parsed command line.
struct BrokerArgs {
    /// NATS server URL.
    uri: String,
    /// Control subject.
    control: String,
    /// Event subject.
    events: String,
    /// Optional `nats-server` binary to spawn for this session.
    spawn: Option<PathBuf>,
    /// Pretty-print message payloads (default: one line per message).
    pretty: bool,
}

impl BrokerArgs {
    fn parse() -> Result<Self, String> {
        let mut parsed = Self {
            uri: "nats://127.0.0.1:4222".to_owned(),
            control: "control".to_owned(),
            events: "events".to_owned(),
            spawn: None,
            pretty: false,
        };
        let mut args = std::env::args_os().skip(1);
        while let Some(arg) = args.next() {
            let mut value = |name: &str| -> Result<String, String> {
                args.next()
                    .map(|v| v.to_string_lossy().into_owned())
                    .ok_or_else(|| format!("missing value for `{name}`\n\n{}", Self::usage()))
            };
            match arg.to_string_lossy().as_ref() {
                "--uri" => parsed.uri = value("--uri")?,
                "--control" => parsed.control = value("--control")?,
                "--events" => parsed.events = value("--events")?,
                "--spawn" => parsed.spawn = Some(PathBuf::from(value("--spawn")?)),
                "--pretty" => parsed.pretty = true,
                other => {
                    return Err(format!("unknown argument `{other}`\n\n{}", Self::usage()));
                }
            }
        }
        Ok(parsed)
    }

    fn usage() -> String {
        "usage: dummy-broker [--uri nats://127.0.0.1:4222] \
         [--control control] [--events events] [--spawn <nats-server.exe>] [--pretty]"
            .to_owned()
    }
}

/// Running traffic accounting for the summary line.
#[derive(Debug, Default)]
struct Traffic {
    /// Messages per canonical event type (unparsed traffic is not counted).
    per_type: BTreeMap<String, u64>,
    /// Total parsed messages per channel.
    control: u64,
    events: u64,
    /// Bytes that failed envelope parsing.
    unparsed: u64,
    /// Sequence gaps seen (messages lost before the broker).
    gaps: u64,
    /// Total missing sequence numbers across all gaps.
    missing_seqs: u64,
    /// Sequence regressions (publisher restart or a second publisher).
    regressions: u64,
}

/// Per-channel monotonic sequence tracker.
#[derive(Debug, Default)]
struct SeqTracker {
    last: Option<u64>,
}

/// What a new sequence number means relative to the previous one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeqVerdict {
    /// Exactly `last + 1` (or the first observation).
    InOrder,
    /// Numbers were skipped; `missing` messages likely never arrived.
    Gap {
        /// Count of skipped sequence numbers.
        missing: u64,
    },
    /// Went backwards: publisher restart or a second publisher.
    Regression,
}

impl SeqTracker {
    fn observe(&mut self, seq: u64) -> SeqVerdict {
        let Some(last) = self.last else {
            self.last = Some(seq);
            return SeqVerdict::InOrder;
        };
        // checked_add: a hostile `u64::MAX` must regress, not overflow.
        match last.checked_add(1).and_then(|next| seq.checked_sub(next)) {
            Some(missing) if missing > 0 => {
                self.last = Some(seq);
                SeqVerdict::Gap { missing }
            }
            Some(_) => {
                self.last = Some(seq);
                SeqVerdict::InOrder
            }
            // seq <= last: publisher restart or a second publisher.
            None => SeqVerdict::Regression,
        }
    }
}

/// Print-and-count sink for both channels.
struct Observer {
    /// Accumulated traffic stats.
    traffic: Traffic,
    /// Sequence state per channel.
    control_seqs: SeqTracker,
    event_seqs: SeqTracker,
    /// Pretty-print payloads instead of one line per message.
    pretty: bool,
}

impl Observer {
    fn new(pretty: bool) -> Self {
        Self {
            traffic: Traffic::default(),
            control_seqs: SeqTracker::default(),
            event_seqs: SeqTracker::default(),
            pretty,
        }
    }

    fn seqs(&mut self, channel: Channel) -> &mut SeqTracker {
        match channel {
            Channel::Control => &mut self.control_seqs,
            Channel::Events => &mut self.event_seqs,
        }
    }

    /// Parse one message, print it, and account for it.
    fn observe(&mut self, channel: Channel, payload: &[u8]) {
        match serde_json::from_slice::<Envelope>(payload) {
            Ok(envelope) => {
                *match channel {
                    Channel::Control => &mut self.traffic.control,
                    Channel::Events => &mut self.traffic.events,
                } += 1;
                *self
                    .traffic
                    .per_type
                    .entry(envelope.event_type.as_str().to_owned())
                    .or_default() += 1;
                match self.seqs(channel).observe(envelope.seq) {
                    SeqVerdict::InOrder => {}
                    SeqVerdict::Gap { missing } => {
                        self.traffic.gaps += 1;
                        self.traffic.missing_seqs += missing;
                        eprintln!(
                            "WARN [{}] sequence gap: {} messages missing before seq {}",
                            channel.label(),
                            missing,
                            envelope.seq
                        );
                    }
                    SeqVerdict::Regression => {
                        self.traffic.regressions += 1;
                        eprintln!(
                            "WARN [{}] sequence regression at seq {} (publisher restart?)",
                            channel.label(),
                            envelope.seq
                        );
                    }
                }
                let data = if self.pretty {
                    serde_json::to_string_pretty(&envelope.data).unwrap_or_default()
                } else {
                    serde_json::to_string(&envelope.data).unwrap_or_default()
                };
                println!(
                    "[{}] #{} {} ts={} study={} session={}",
                    channel.label(),
                    envelope.seq,
                    envelope.event_type.as_str(),
                    envelope.ts,
                    envelope.study,
                    envelope.session
                );
                if self.pretty {
                    println!("{data}");
                } else {
                    println!("    data: {data}");
                }
            }
            Err(error) => {
                self.traffic.unparsed += 1;
                // Char-boundary-safe truncation: the bytes are hostile.
                let raw = String::from_utf8_lossy(payload).chars().take(1000).collect::<String>();
                eprintln!("WARN [{}] unparsable message ({error}): {raw}", channel.label());
            }
        }
    }

    /// End-of-session summary.
    fn summary(&self) -> String {
        let traffic = &self.traffic;
        let mut lines = vec![format!(
            "control: {} messages, events: {} messages",
            traffic.control, traffic.events
        )];
        for (event_type, count) in &traffic.per_type {
            lines.push(format!("  {event_type}: {count}"));
        }
        lines.push(format!(
            "sequence: {} gaps ({} missing), {} regressions, {} unparsable messages",
            traffic.gaps, traffic.missing_seqs, traffic.regressions, traffic.unparsed
        ));
        lines.join("\n")
    }
}

/// Parse `scheme://host[:port]` into bind/connect coordinates (default port
/// 4222). IPv6 hosts must be bracketed.
fn split_host_port(uri: &str) -> Option<(String, u16)> {
    let rest = uri.split_once("://").map_or(uri, |(_, rest)| rest);
    let rest = rest.split(['/', '?']).next().unwrap_or("");
    if rest.is_empty() {
        return None;
    }
    if let Some(bracketed) = rest.strip_prefix('[') {
        let (host, tail) = bracketed.split_once(']')?;
        let port = tail.strip_prefix(':').and_then(|raw| raw.parse().ok()).unwrap_or(4222);
        return Some((host.to_owned(), port));
    }
    match rest.rsplit_once(':') {
        Some((host, port)) => Some((host.to_owned(), port.parse().ok()?)),
        None => Some((rest.to_owned(), 4222)),
    }
}

/// Spawn the given `nats-server` bound to the `--uri` coordinates.
fn spawn_server(path: &std::path::Path, uri: &str) -> anyhow::Result<tokio::process::Child> {
    let Some((host, port)) = split_host_port(uri) else {
        anyhow::bail!("cannot parse `{uri}` as nats://host:port for --spawn");
    };
    let child = tokio::process::Command::new(path)
        .arg("-a")
        .arg(&host)
        .arg("-p")
        .arg(port.to_string())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| anyhow::anyhow!("spawning {}: {error}", path.display()))?;
    println!("spawned {} (bind {host}:{port})", path.display());
    Ok(child)
}

/// Poll the server port until it accepts (bounded; the spawn just started).
async fn wait_ready(host: &str, port: u16) -> bool {
    for _ in 0..30 {
        if tokio::net::TcpStream::connect((host, port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = BrokerArgs::parse().map_err(|error| anyhow::anyhow!("{error}"))?;
    let mut spawned = match &args.spawn {
        Some(path) => Some(spawn_server(path, &args.uri)?),
        None => None,
    };
    if spawned.is_some() {
        let Some((host, port)) = split_host_port(&args.uri) else {
            anyhow::bail!("cannot parse `{}` as nats://host:port", args.uri);
        };
        if !wait_ready(&host, port).await {
            anyhow::bail!("spawned nats-server never accepted connections on {host}:{port}");
        }
    }

    let mut client = None;
    for attempt in 1..=CONNECT_ATTEMPTS {
        match async_nats::connect(&args.uri).await {
            Ok(connected) => {
                client = Some(connected);
                break;
            }
            Err(error) => {
                eprintln!("connect attempt {attempt}/{CONNECT_ATTEMPTS} failed: {error}");
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let Some(client) = client else {
        anyhow::bail!("could not connect to {} after {CONNECT_ATTEMPTS} attempts", args.uri);
    };
    println!(
        "connected to {}; observing {} + {} (Ctrl+C for summary)",
        args.uri, args.control, args.events
    );

    let mut control = client.subscribe(args.control.clone()).await?;
    let mut events = client.subscribe(args.events.clone()).await?;

    let mut observer = Observer::new(args.pretty);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            message = control.next() => match message {
                Some(message) => observer.observe(Channel::Control, &message.payload),
                None => break,
            },
            message = events.next() => match message {
                Some(message) => observer.observe(Channel::Events, &message.payload),
                None => break,
            },
        }
    }

    if let Some(mut child) = spawned.take() {
        let _ = child.kill().await;
    }
    println!("\n--- dummy-broker summary ---\n{}", observer.summary());
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn uri_parsing_covers_host_port_ipv6_and_garbage() {
        assert_eq!(split_host_port("nats://127.0.0.1:4222"), Some(("127.0.0.1".to_owned(), 4222)));
        assert_eq!(split_host_port("nats://broker.lab"), Some(("broker.lab".to_owned(), 4222)));
        assert_eq!(split_host_port("nats://[::1]:4223"), Some(("::1".to_owned(), 4223)));
        assert_eq!(split_host_port("nats://[::1]"), Some(("::1".to_owned(), 4222)));
        // Trailing path is ignored.
        assert_eq!(
            split_host_port("nats://broker.lab:4222/"),
            Some(("broker.lab".to_owned(), 4222))
        );
        assert_eq!(split_host_port(""), None);
        assert_eq!(split_host_port("nats://host:notaport"), None);
    }

    #[test]
    fn seq_tracker_counts_gaps_and_regressions() {
        let mut tracker = SeqTracker::default();
        assert_eq!(tracker.observe(1), SeqVerdict::InOrder);
        assert_eq!(tracker.observe(2), SeqVerdict::InOrder);
        assert_eq!(tracker.observe(6), SeqVerdict::Gap { missing: 3 });
        assert_eq!(tracker.observe(6), SeqVerdict::Regression);
        assert_eq!(tracker.observe(7), SeqVerdict::InOrder);
    }

    #[test]
    fn sequence_zero_regression_is_detected() {
        let mut tracker = SeqTracker::default();
        assert_eq!(tracker.observe(0), SeqVerdict::InOrder);
        // A restarted publisher starts from 0 again.
        assert_eq!(tracker.observe(0), SeqVerdict::Regression);
    }

    fn envelope_json(seq: u64, event_type: &str) -> Vec<u8> {
        format!(
            "{{\"v\":3,\"type\":\"{event_type}\",\"ts\":1000,\
             \"study\":\"00000000-0000-0000-0000-000000000000\",\"session\":1,\
             \"seq\":{seq},\"data\":{{}}}}"
        )
        .into_bytes()
    }

    #[test]
    fn observer_counts_channels_types_and_loss_separately() {
        let mut observer = Observer::new(false);
        observer.observe(Channel::Events, &envelope_json(1, "process.started"));
        observer.observe(Channel::Events, &envelope_json(4, "process.started"));
        observer.observe(Channel::Events, b"not json at all");
        observer.observe(Channel::Control, &envelope_json(1, "control.keepalive"));
        // A different channel's seq numbering must not trip the other's tracker.
        observer.observe(Channel::Control, &envelope_json(2, "control.keepalive"));

        let traffic = &observer.traffic;
        assert_eq!(traffic.events, 2);
        assert_eq!(traffic.unparsed, 1);
        assert_eq!(traffic.control, 2);
        assert_eq!(traffic.per_type.get("process.started"), Some(&2));
        assert_eq!(traffic.per_type.get("control.keepalive"), Some(&2));
        assert_eq!(traffic.gaps, 1);
        assert_eq!(traffic.missing_seqs, 2);
        assert_eq!(traffic.regressions, 0);

        let summary = observer.summary();
        assert!(summary.contains("control: 2 messages"), "{summary}");
        assert!(summary.contains("1 gaps (2 missing)"), "{summary}");
    }
}
