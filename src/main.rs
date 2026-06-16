use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use palisade::server::{
    ServerState, serve, shutdown_signal, spawn_health_checker, spawn_rate_limit_cleanup,
};
use palisade::{
    Config, IpRateLimiter, LoadBalancer, UpstreamPool, build_client, build_https_client,
};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

/// An HTTP reverse proxy with load balancing, rate limiting, and TLS support.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Path to the YAML configuration file.
    #[arg(short, long, default_value = "./Config.yml")]
    config: String,

    /// Log output format (pretty | json).
    #[arg(long, default_value = "pretty")]
    log_format: LogFormat,

    /// Log verbosity level, overriding the `RUST_LOG` environment variable.
    #[arg(long)]
    log_level: Option<String>,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum LogFormat {
    Pretty,
    Json,
}

fn init_tracing(format: &LogFormat, level_override: Option<&str>) {
    let filter = level_override.map_or_else(
        || EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        EnvFilter::new,
    );

    match format {
        LogFormat::Pretty => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .init();
        }
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .with_target(false)
                .init();
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    init_tracing(&cli.log_format, cli.log_level.as_deref());

    let config = Config::load_from_file(&cli.config)
        .and_then(|c| c.into_runtime())
        .unwrap_or_else(|e| {
            error!(%e, "failed to load configuration");
            std::process::exit(1);
        });

    let tls_acceptor = config.tls.as_ref().map(|tls_cfg| {
        palisade::tls::build_tls_acceptor(tls_cfg).unwrap_or_else(|e| {
            error!(%e, "failed to initialize TLS");
            std::process::exit(1);
        })
    });

    let upstream_is_https = config.has_https_upstream();
    let pool = UpstreamPool::from_validated(&config.upstreams, config.health_check_cooldown);
    let balancer = LoadBalancer::new(pool);

    let rate_limiter = config.rate_limit.as_ref().map(|rl_cfg| {
        info!(
            requests_per_second = rl_cfg.requests_per_second,
            burst = rl_cfg.burst,
            "per-IP rate limiting enabled"
        );
        IpRateLimiter::from_config(rl_cfg).unwrap_or_else(|e| {
            error!(%e, "failed to initialize rate limiter");
            std::process::exit(1);
        })
    });

    info!(
        upstreams = config.upstreams.len(),
        blocked_headers = config.blocked_headers.len(),
        blocked_params = config.blocked_params.len(),
        mask_rules = config.mask_rules.len(),
        max_body_size = config.max_body_size,
        connect_timeout = ?config.connect_timeout,
        request_timeout = ?config.request_timeout,
        max_concurrent_requests = config.max_concurrent_requests,
        tls_termination = tls_acceptor.is_some(),
        tls_origination = upstream_is_https,
        active_health_checks = config.health_check.is_some(),
        rate_limiting = rate_limiter.is_some(),
        "configuration loaded"
    );

    for (i, u) in config.upstreams.iter().enumerate() {
        info!(
            index = i,
            upstream = %u.uri,
            weight = u.weight,
            "registered upstream backend"
        );
    }

    let semaphore = Arc::new(Semaphore::new(config.max_concurrent_requests));
    let concurrency_limit = config.max_concurrent_requests;
    let addr = config.listen;
    let config = Arc::new(config);

    let listener = TcpListener::bind(addr).await.unwrap_or_else(|e| {
        error!(%e, %addr, "failed to bind");
        std::process::exit(1);
    });

    info!(%addr, "listening");

    let health_check_handle = config.health_check.as_ref().map(|hc| {
        let probe_client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(palisade::tls::build_https_connector(config.connect_timeout));
        spawn_health_checker(
            balancer.clone(),
            probe_client,
            Duration::from_secs(hc.interval),
            &hc.path,
            config.failure_threshold,
            config.healthy_threshold,
            Duration::from_secs(hc.timeout),
        )
    });

    let cleanup_handle = rate_limiter
        .as_ref()
        .map(|rl| spawn_rate_limit_cleanup(rl.clone()));

    let state = ServerState {
        config: Arc::clone(&config),
        balancer,
        semaphore,
        concurrency_limit,
        rate_limiter,
        tls_acceptor,
    };

    if upstream_is_https {
        let client = build_https_client(&config);
        serve(listener, client, state, shutdown_signal()).await;
    } else {
        let client = build_client(&config);
        serve(listener, client, state, shutdown_signal()).await;
    }

    if let Some(handle) = health_check_handle {
        handle.abort();
    }

    if let Some(handle) = cleanup_handle {
        handle.abort();
    }

    info!("shutdown complete");
}
