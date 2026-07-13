use std::path::Path;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// Initializes JSON-structured tracing, level controlled by `RUST_LOG`
/// (defaults to `info`). Always writes to stdout (so `docker logs`/
/// `journalctl` keep working); when `LITTERAE_LOG_DIR` is set, *also*
/// writes daily-rotating JSON log files there -- a log-watching tool like
/// CrowdSec can't tail a container's stdout without extra plumbing, but
/// can tail a bind-mounted file (spec §8.4 hardening). Both sinks get
/// every line; this is additive, not a switch between the two.
///
/// Returns a guard that must be kept alive for the process lifetime when
/// file logging is active (dropping it stops the background flush thread
/// and drops buffered-but-unwritten log lines).
#[must_use]
pub fn init() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stdout_layer = fmt::layer().json();

    match std::env::var("LITTERAE_LOG_DIR") {
        Ok(dir) => {
            let appender = tracing_appender::rolling::daily(Path::new(&dir), "litterae.log");
            let (writer, guard) = tracing_appender::non_blocking(appender);
            let file_layer = fmt::layer().json().with_writer(writer);
            tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .with(file_layer)
                .init();
            Some(guard)
        }
        Err(_) => {
            tracing_subscriber::registry().with(filter).with(stdout_layer).init();
            None
        }
    }
}
