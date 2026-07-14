//! The binary: config load, runtime, wire listeners, graceful shutdown.

use std::path::PathBuf;
use std::sync::Arc;

use common::Config;
use store::{BlobStore, MetadataStore};

mod serve;

#[tokio::main]
async fn main() {
    // Held for the process lifetime: dropping it stops the background
    // flush thread when file logging (LITTERAE_LOG_DIR) is active.
    let _log_guard = common::tracing_init::init();

    let config_path = std::env::var("LITTERAE_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("litterae.toml"));

    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, path = %config_path.display(), "failed to load config");
            std::process::exit(1);
        }
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("provision") => return provision(&config, &args[1..]),
        Some("dkim-init") => return dkim_init(&config, &args[1..]),
        Some("domain") => return domain_cli(&config, &args[1..]),
        _ => {}
    }

    tracing::info!(domain = %config.server.domain, "litterae starting");

    let blobs = Arc::new(BlobStore::open(&config.storage.blob_dir).expect("open blob store"));
    let metadata =
        Arc::new(MetadataStore::open(&config.storage.sqlite_path).expect("open metadata store"));
    // Each owns its own connection to the same file as `metadata` (SQLite
    // WAL mode allows multiple connections to one file); `auth` owns the
    // accounts table, `queue` owns outbound/dkim_keys, `admin` owns
    // admins/domains, `store` owns blobs/messages.
    let auth_store =
        Arc::new(auth::AuthStore::open(&config.storage.sqlite_path).expect("open auth store"));
    let queue_store =
        Arc::new(queue::QueueStore::open(&config.storage.sqlite_path).expect("open queue store"));
    let admin_store =
        Arc::new(admin::AdminStore::open(&config.storage.sqlite_path).expect("open admin store"));
    let audit_store =
        Arc::new(audit::AuditStore::open(&config.storage.sqlite_path).expect("open audit store"));
    let argon2_config = Arc::new(config.argon2.clone());

    if let Some((username, password)) = config.admin.bootstrap_credentials() {
        match admin_store.bootstrap(username, password.as_bytes(), &argon2_config) {
            Ok(Some(pk)) => {
                tracing::info!(username, "admin bootstrap created");
                if let Err(e) = audit_store.bootstrap_keys(&pk) {
                    tracing::error!(error = %e, "audit log key bootstrap failed");
                }
            }
            Ok(None) => tracing::info!(username, "admin bootstrap checked (admin already exists)"),
            Err(e) => tracing::error!(error = %e, "admin bootstrap failed"),
        }
    }

    let scanner = Arc::new(scan::Scanner::from_config(&config.antispam, &config.antivirus));
    tracing::info!(
        antispam = config.antispam.is_enabled(),
        antivirus = config.antivirus.is_enabled(),
        "content scanning configured",
    );

    // One process-wide instance: inbound delivery (smtp-in), local DSN
    // delivery (the outbound worker), and JMAP's own mutations all publish
    // to it; JMAP's `/jmap/sse` endpoint is the only subscriber.
    let notifier = Arc::new(common::changes::ChangeNotifier::new());

    let smtp_result = smtp_in::run(
        &config.smtp,
        config.server.domain.clone(),
        auth_store.clone(),
        admin_store.clone(),
        blobs.clone(),
        metadata.clone(),
        scanner,
        audit_store.clone(),
        notifier.clone(),
    );

    let jmap_state = jmap::AppState::new(
        auth_store.clone(),
        blobs.clone(),
        metadata.clone(),
        audit_store.clone(),
        argon2_config.clone(),
        queue_store.clone(),
        notifier.clone(),
    );
    let jmap_router = jmap::build_router(jmap_state);
    let jmap_addr = config.jmap.listen_addr.clone();
    let jmap_tls = match (&config.jmap.tls_cert_path, &config.jmap.tls_key_path) {
        (Some(cert), Some(key)) => match common::tls::load_server_config(cert, key) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                tracing::error!(error = %e, "failed to load jmap TLS cert/key");
                std::process::exit(1);
            }
        },
        _ => None,
    };
    tracing::info!(addr = %jmap_addr, tls = jmap_tls.is_some(), "jmap listening");
    let jmap_result = serve::serve(&jmap_addr, jmap_router, jmap_tls);

    let log_dir = std::env::var("LITTERAE_LOG_DIR").ok().map(PathBuf::from);
    // Independent from the worker's own resolver below (same reasoning as
    // the worker's independent store handles) -- domain verification's
    // live TXT lookups have nothing to do with outbound delivery.
    let admin_dns_resolver = Arc::new(dns::Resolver::new().expect("build DNS resolver for admin"));
    let admin_state = admin::AppState::new(
        admin_store,
        auth_store.clone(),
        queue_store.clone(),
        audit_store.clone(),
        argon2_config.clone(),
        log_dir,
        admin_dns_resolver,
    );
    let admin_router = admin::build_router(admin_state);
    let admin_addr = config.admin.listen_addr.clone();
    let admin_tls = match (&config.admin.tls_cert_path, &config.admin.tls_key_path) {
        (Some(cert), Some(key)) => match common::tls::load_server_config(cert, key) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                tracing::error!(error = %e, "failed to load admin TLS cert/key");
                std::process::exit(1);
            }
        },
        _ => None,
    };
    tracing::info!(addr = %admin_addr, tls = admin_tls.is_some(), "admin listening");
    let admin_result = serve::serve(&admin_addr, admin_router, admin_tls);

    // The outbound worker has no TLS dependency (opportunistic, same as
    // inbound); it always runs as a background task.
    let resolver = dns::Resolver::new().expect("build DNS resolver");
    let worker = queue::Worker::new(
        queue::QueueStore::open(&config.storage.sqlite_path).expect("open queue store for worker"),
        BlobStore::open(&config.storage.blob_dir).expect("open blob store for worker"),
        MetadataStore::open(&config.storage.sqlite_path).expect("open metadata store for worker"),
        auth::AuthStore::open(&config.storage.sqlite_path).expect("open auth store for worker"),
        audit_store.clone(),
        resolver,
        config.server.domain.clone(),
        notifier,
    );
    tokio::spawn(async move { worker.run().await });

    // Submission requires TLS (no plaintext mode); if no cert is
    // configured, log once and leave the slot permanently pending rather
    // than aborting the whole process over an optional listener.
    let submission_result = async {
        if config.submission.tls_cert_path.is_none() || config.submission.tls_key_path.is_none() {
            tracing::warn!("submission disabled: no TLS cert configured");
            std::future::pending::<()>().await;
            unreachable!();
        }
        submission::run(
            &config.submission,
            config.server.domain.clone(),
            auth_store,
            queue_store,
            blobs,
            audit_store,
            argon2_config,
        )
        .await
    };

    tokio::select! {
        result = smtp_result => {
            if let Err(e) = result {
                tracing::error!(error = %e, "smtp-in listener exited");
                std::process::exit(1);
            }
        }
        result = jmap_result => {
            if let Err(e) = result {
                tracing::error!(error = %e, "jmap listener exited");
                std::process::exit(1);
            }
        }
        result = admin_result => {
            if let Err(e) = result {
                tracing::error!(error = %e, "admin listener exited");
                std::process::exit(1);
            }
        }
        result = submission_result => {
            if let Err(e) = result {
                tracing::error!(error = %e, "submission listener exited");
                std::process::exit(1);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
        }
    }
}

/// `litterae provision <local_part> <domain> <password>` -- mints a new
/// account against the configured storage and exits. Prefer the admin API
/// for day-to-day use; this stays for scripting/first-run setups.
fn provision(config: &Config, args: &[String]) {
    let [local_part, domain, password] = args else {
        eprintln!("usage: litterae provision <local_part> <domain> <password>");
        std::process::exit(2);
    };

    let auth_store = auth::AuthStore::open(&config.storage.sqlite_path).expect("open auth store");
    match auth_store.provision(local_part, domain, password.as_bytes(), &config.argon2) {
        Ok(account) => println!("provisioned {} (id {})", account.address(), account.id),
        Err(e) => {
            eprintln!("failed to provision account: {e}");
            std::process::exit(1);
        }
    }
}

/// `litterae dkim-init <domain>` -- generates (or reuses) the domain's DKIM
/// key and prints the DNS TXT record to publish. Also runs automatically
/// the first time a message from that domain is queued, but this lets an
/// operator publish DNS *before* sending mail.
fn dkim_init(config: &Config, args: &[String]) {
    let [domain] = args else {
        eprintln!("usage: litterae dkim-init <domain>");
        std::process::exit(2);
    };

    let queue_store =
        queue::QueueStore::open(&config.storage.sqlite_path).expect("open queue store");
    match queue_store.ensure_dkim_key(domain) {
        Ok(key) => {
            println!("DKIM key ready for {domain} (selector: {})", key.selector);
            println!("Publish this TXT record:");
            println!("  {}._domainkey.{domain}  IN TXT  \"{}\"", key.selector, key.dns_txt_record());
        }
        Err(e) => {
            eprintln!("failed to generate DKIM key: {e}");
            std::process::exit(1);
        }
    }
}

/// `litterae domain add|list|set-catchall` -- the CLI's counterpart to the
/// admin area's domain management, covering the same operations.
fn domain_cli(config: &Config, args: &[String]) {
    let admin_store =
        admin::AdminStore::open(&config.storage.sqlite_path).expect("open admin store");

    let usage = || {
        eprintln!("usage:");
        eprintln!("  litterae domain add <name> [catch_all_local_part]");
        eprintln!("  litterae domain list");
        eprintln!("  litterae domain set-catchall <name> <local_part|none>");
        std::process::exit(2);
    };

    match args.split_first() {
        Some((cmd, [name])) if cmd == "add" => {
            match admin_store.create_domain(name, None) {
                Ok(domain) => println!("hosting {}", domain.name),
                Err(e) => {
                    eprintln!("failed to add domain: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some((cmd, [name, catch_all])) if cmd == "add" => {
            match admin_store.create_domain(name, Some(catch_all)) {
                Ok(domain) => println!("hosting {} (catch-all: {catch_all})", domain.name),
                Err(e) => {
                    eprintln!("failed to add domain: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some((cmd, [])) if cmd == "list" => match admin_store.list_domains() {
            Ok(domains) if domains.is_empty() => println!("no domains hosted yet"),
            Ok(domains) => {
                for d in domains {
                    println!(
                        "{}  (catch-all: {})",
                        d.name,
                        d.catch_all_local_part.as_deref().unwrap_or("none")
                    );
                }
            }
            Err(e) => {
                eprintln!("failed to list domains: {e}");
                std::process::exit(1);
            }
        },
        Some((cmd, [name, local_part])) if cmd == "set-catchall" => {
            let catch_all = if local_part == "none" { None } else { Some(local_part.as_str()) };
            let Ok(Some(domain)) = admin_store.get_domain_by_name(name) else {
                eprintln!("no such hosted domain: {name}");
                std::process::exit(1);
            };
            match admin_store.set_catch_all(domain.id, catch_all) {
                Ok(()) => println!("updated catch-all for {name}"),
                Err(e) => {
                    eprintln!("failed to update catch-all: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => usage(),
    }
}
