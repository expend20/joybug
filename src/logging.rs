use tracing_subscriber::EnvFilter;

pub fn init_subscriber() {
    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
} 