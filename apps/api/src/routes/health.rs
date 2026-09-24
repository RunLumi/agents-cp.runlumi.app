use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "lumi-agents-control-plane-api",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_shape_is_stable() {
        let value = serde_json::to_value(HealthResponse {
            status: "ok",
            service: "lumi-agents-control-plane-api",
        })
        .expect("health response must serialize");

        assert_eq!(value["status"], "ok");
        assert_eq!(value["service"], "lumi-agents-control-plane-api");
    }
}
