use axum::{routing::get, Router};
use worker::Env;

use crate::routes::health::health;

pub fn router(_env: Env) -> Router {
    Router::new().route("/api/health", get(health))
}
