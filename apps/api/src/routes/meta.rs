use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct MetaResponse {
    api_version: &'static str,
    contract_version: &'static str,
    service: &'static str,
}

pub async fn meta() -> Json<MetaResponse> {
    Json(MetaResponse {
        api_version: "v1",
        contract_version: "p01-cg-v1",
        service: "lumi-agents-control-plane-api",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_shape_matches_the_frozen_contract() {
        let value = serde_json::to_value(MetaResponse {
            api_version: "v1",
            contract_version: "p01-cg-v1",
            service: "lumi-agents-control-plane-api",
        })
        .expect("meta response must serialize");

        assert_eq!(value["api_version"], "v1");
        assert_eq!(value["contract_version"], "p01-cg-v1");
        assert_eq!(value["service"], "lumi-agents-control-plane-api");
    }
}
