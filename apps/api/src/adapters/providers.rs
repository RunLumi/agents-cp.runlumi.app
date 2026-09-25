//! Provider adapter boundary for P04.
//!
//! Provider-specific request shapes and stream errors stop here. The gateway
//! receives a typed stream and normalized status, while credentials are added
//! only while constructing the trusted outbound request.

use std::fmt;
use std::net::IpAddr;

use futures_util::{StreamExt, stream, stream::LocalBoxStream};
use serde_json::{Value, json};
use wasm_bindgen::JsValue;
use worker::{AbortSignal, Fetch, Headers, Method, Request, RequestInit, RequestRedirect};

use crate::modules::inference::{
    AdapterError, AdapterErrorKind, InferenceMessage, InferenceRequest, MessageRole,
    ProviderStreamEvent, SseDecoder, normalize_adapter_error,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdapterKind {
    OpenAiCompatible,
    Anthropic,
    Mock,
}

impl AdapterKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "openai_compatible" => Some(Self::OpenAiCompatible),
            "anthropic" => Some(Self::Anthropic),
            "mock" => Some(Self::Mock),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SsrfError {
    InvalidUrl,
    SchemeNotAllowed,
    PrivateDestination,
    HostNotAllowlisted,
    CredentialsNotAllowed,
}

impl fmt::Display for SsrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidUrl => "provider endpoint URL is invalid",
            Self::SchemeNotAllowed => "provider endpoint scheme is not allowed",
            Self::PrivateDestination => "provider endpoint resolves to a private destination",
            Self::HostNotAllowlisted => "provider endpoint host is not allowlisted",
            Self::CredentialsNotAllowed => "provider endpoint credentials are not allowed",
        })
    }
}

impl std::error::Error for SsrfError {}

/// A small adapter contract used by the gateway. It intentionally has no
/// provider SDK types in its surface.
pub trait ProviderAdapterContract {
    fn kind(&self) -> AdapterKind;
    fn translate_request(
        &self,
        request: &InferenceRequest,
        provider_model_id: &str,
    ) -> Result<String, AdapterError>;
    fn classify_status(&self, status_code: u16) -> AdapterError;
}

#[derive(Clone, Copy, Debug)]
pub struct ProviderAdapter;

impl ProviderAdapterContract for ProviderAdapter {
    fn kind(&self) -> AdapterKind {
        // Dispatch is selected from the trusted catalog record. This default
        // keeps the trait useful for callers that only need OpenAI-compatible
        // translation; the gateway dispatches by its explicit kind below.
        AdapterKind::OpenAiCompatible
    }

    fn translate_request(
        &self,
        request: &InferenceRequest,
        provider_model_id: &str,
    ) -> Result<String, AdapterError> {
        translate_openai_request(request, provider_model_id)
    }

    fn classify_status(&self, status_code: u16) -> AdapterError {
        normalize_adapter_error(status_code, "")
    }
}

pub struct ProviderDispatch {
    pub status_code: u16,
    pub content_type: Option<String>,
    pub provider_request_id: Option<String>,
    pub stream: LocalBoxStream<'static, Result<Vec<u8>, worker::Error>>,
}

impl fmt::Debug for ProviderDispatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderDispatch")
            .field("status_code", &self.status_code)
            .field("content_type", &self.content_type)
            .field("provider_request_id", &self.provider_request_id)
            .field("stream", &"[redacted]")
            .finish()
    }
}

pub fn translate_openai_request(
    request: &InferenceRequest,
    provider_model_id: &str,
) -> Result<String, AdapterError> {
    let messages = request
        .messages
        .iter()
        .map(translate_openai_message)
        .collect::<Result<Vec<_>, _>>()?;
    let mut value = json!({
        "model": provider_model_id,
        "messages": messages,
        "stream": request.stream,
    });
    if let Some(max_tokens) = request.max_output_tokens {
        value["max_tokens"] = json!(max_tokens);
    }
    if let Some(temperature) = request.temperature {
        value["temperature"] = json!(temperature);
    }
    if !request.tools.is_empty() {
        value["tools"] = Value::Array(request.tools.clone());
    }
    serde_json::to_string(&value).map_err(|_| invalid_request())
}

fn translate_openai_message(message: &InferenceMessage) -> Result<Value, AdapterError> {
    let role = match message.role {
        MessageRole::System => "system",
        MessageRole::User => "user",
        MessageRole::Assistant => "assistant",
        MessageRole::Tool => "tool",
    };
    let text = message
        .content
        .iter()
        .map(|part| match part {
            crate::modules::inference::ContentPart::Text { text } => Ok(text.as_str()),
        })
        .collect::<Result<Vec<_>, AdapterError>>()?
        .join("");
    if text.len() > 256 * 1024 {
        return Err(invalid_request());
    }
    Ok(json!({ "role": role, "content": text }))
}

pub fn translate_anthropic_request(
    request: &InferenceRequest,
    provider_model_id: &str,
) -> Result<String, AdapterError> {
    let mut system = Vec::new();
    let mut messages = Vec::new();
    for message in &request.messages {
        let text = message
            .content
            .iter()
            .map(|part| match part {
                crate::modules::inference::ContentPart::Text { text } => text.as_str(),
            })
            .collect::<Vec<_>>()
            .join("");
        match message.role {
            MessageRole::System => system.push(text),
            _ => messages.push(json!({"role": "user", "content": text})),
        }
    }
    let mut value = json!({
        "model": provider_model_id,
        "messages": messages,
        "max_tokens": request.max_output_tokens.unwrap_or(1024),
        "stream": request.stream,
    });
    if !system.is_empty() {
        value["system"] = json!(system.join("\n"));
    }
    if let Some(temperature) = request.temperature {
        value["temperature"] = json!(temperature);
    }
    if !request.tools.is_empty() {
        let tools = request
            .tools
            .iter()
            .filter_map(|tool| {
                let function = tool.get("function")?;
                let name = function.get("name")?.as_str()?;
                let mut translated = json!({
                    "name": name,
                    "input_schema": function
                        .get("parameters")
                        .cloned()
                        .unwrap_or_else(|| json!({"type": "object"})),
                });
                if let Some(description) = function.get("description") {
                    translated["description"] = description.clone();
                }
                Some(translated)
            })
            .collect::<Vec<_>>();
        if tools.len() == request.tools.len() {
            value["tools"] = Value::Array(tools);
        } else {
            return Err(invalid_request());
        }
    }
    serde_json::to_string(&value).map_err(|_| invalid_request())
}

/// Validate a server-controlled endpoint before any outbound fetch. The
/// allowlist is exact-host matching; wildcard or caller-provided URLs are not
/// supported.
pub fn validate_endpoint_url(
    endpoint: &str,
    allowlist: &[String],
    allow_local_development: bool,
) -> Result<(), SsrfError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty()
        || endpoint.len() > 2048
        || endpoint.chars().any(char::is_control)
        || endpoint.contains('?')
        || endpoint.contains('#')
        || endpoint.contains('@')
    {
        return Err(SsrfError::InvalidUrl);
    }
    if endpoint.starts_with("mock://") {
        return if allow_local_development
            && matches!(
                endpoint,
                "mock://lumi-fail"
                    | "mock://lumi-success"
                    | "mock://lumi-post-output-failure"
                    | "mock://lumi-timeout"
            ) {
            Ok(())
        } else {
            Err(SsrfError::SchemeNotAllowed)
        };
    }
    let Some((scheme, remainder)) = endpoint.split_once("://") else {
        return Err(SsrfError::InvalidUrl);
    };
    if scheme != "https" && !(allow_local_development && scheme == "http") {
        return Err(SsrfError::SchemeNotAllowed);
    }
    let authority = remainder.split('/').next().unwrap_or_default();
    let host = if let Some(end) = authority.strip_prefix('[') {
        end.split(']')
            .next()
            .filter(|value| !value.is_empty())
            .ok_or(SsrfError::InvalidUrl)?
    } else {
        authority
            .split_once(':')
            .map_or(authority, |(host, _port)| host)
    };
    if host.is_empty()
        || host.chars().any(char::is_whitespace)
        || host.contains('[')
        || host.contains(']')
    {
        return Err(SsrfError::InvalidUrl);
    }
    let lower = host.trim_end_matches('.').to_ascii_lowercase();
    let private_ip = lower.parse::<IpAddr>().is_ok_and(|address| match address {
        IpAddr::V4(value) => {
            value.is_private()
                || value.is_loopback()
                || value.is_link_local()
                || value.is_unspecified()
                || value.octets()[0] == 100 && (64..=127).contains(&value.octets()[1])
        }
        IpAddr::V6(value) => {
            value.is_loopback()
                || value.is_unspecified()
                || (value.segments()[0] & 0xfe00) == 0xfc00
                || (value.segments()[0] & 0xffc0) == 0xfe80
        }
    });
    if (lower == "localhost"
        || lower.ends_with(".localhost")
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || private_ip)
        && !allow_local_development
    {
        return Err(SsrfError::PrivateDestination);
    }
    if !allowlist
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&lower))
    {
        return Err(SsrfError::HostNotAllowlisted);
    }
    Ok(())
}

fn endpoint_url(kind: AdapterKind, endpoint: &str) -> Result<String, AdapterError> {
    if kind == AdapterKind::Mock {
        return Ok(endpoint.to_owned());
    }
    let base = endpoint.trim_end_matches('/');
    let path = match kind {
        AdapterKind::Anthropic => "/v1/messages",
        _ => "/v1/chat/completions",
    };
    Ok(format!("{base}{path}"))
}

fn invalid_request() -> AdapterError {
    AdapterError {
        kind: AdapterErrorKind::InvalidRequest,
        retryable: false,
        status_code: None,
    }
}

fn ssrf_error() -> AdapterError {
    AdapterError {
        kind: AdapterErrorKind::InvalidRequest,
        retryable: false,
        status_code: None,
    }
}

fn transport_error() -> AdapterError {
    AdapterError {
        kind: AdapterErrorKind::ConnectionFailed,
        retryable: true,
        status_code: None,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn dispatch(
    kind: AdapterKind,
    endpoint: &str,
    provider_model_id: &str,
    request: &InferenceRequest,
    credential: Option<&str>,
    allowlist: &[String],
    allow_local_development: bool,
    request_id: Option<&str>,
    caller_signal: Option<&AbortSignal>,
    timeout_ms: u32,
) -> Result<ProviderDispatch, AdapterError> {
    if kind == AdapterKind::Mock {
        return mock_dispatch(endpoint, provider_model_id, request);
    }
    validate_endpoint_url(endpoint, allowlist, allow_local_development)
        .map_err(|_| ssrf_error())?;
    let body = match kind {
        AdapterKind::Anthropic => translate_anthropic_request(request, provider_model_id)?,
        _ => translate_openai_request(request, provider_model_id)?,
    };
    let url = endpoint_url(kind, endpoint).map_err(|_| ssrf_error())?;
    let headers = Headers::new();
    headers
        .set("content-type", "application/json")
        .map_err(|_| transport_error())?;
    headers
        .set(
            "accept",
            if request.stream {
                "text/event-stream"
            } else {
                "application/json"
            },
        )
        .map_err(|_| transport_error())?;
    if let Some(secret) = credential {
        match kind {
            AdapterKind::Anthropic => headers.set("x-api-key", secret).map_err(|_| ssrf_error())?,
            _ => headers
                .set("authorization", &format!("Bearer {secret}"))
                .map_err(|_| ssrf_error())?,
        }
    }
    if kind == AdapterKind::Anthropic {
        headers
            .set("anthropic-version", "2023-06-01")
            .map_err(|_| transport_error())?;
    }
    if let Some(request_id) = request_id {
        headers
            .set("x-lumi-request-id", request_id)
            .map_err(|_| transport_error())?;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_redirect(RequestRedirect::Error);
    init.with_headers(headers);
    init.with_body(Some(JsValue::from_str(&body)));
    let timeout = timeout_signal(caller_signal, timeout_ms).ok();
    let response_result = match timeout.as_ref() {
        Some(signal) => {
            Fetch::Request(Request::new_with_init(&url, &init).map_err(|_| transport_error())?)
                .send_with_signal(signal)
                .await
        }
        None => {
            Fetch::Request(Request::new_with_init(&url, &init).map_err(|_| transport_error())?)
                .send()
                .await
        }
    };
    let mut response = match response_result {
        Ok(response) => response,
        Err(_) if timeout.as_ref().is_some_and(|signal| signal.aborted()) => {
            return Err(AdapterError {
                kind: AdapterErrorKind::Timeout,
                retryable: true,
                status_code: None,
            });
        }
        Err(_) => return Err(transport_error()),
    };
    let status = response.status_code();
    if !(200..300).contains(&status) {
        return Err(normalize_adapter_error(status, ""));
    }
    let content_type = response.headers().get("content-type").ok().flatten();
    let provider_request_id = response
        .headers()
        .get("x-request-id")
        .ok()
        .flatten()
        .or_else(|| response.headers().get("request-id").ok().flatten());
    let raw_stream = response
        .stream()
        .map_err(|_| transport_error())?
        .boxed_local();
    let stream = if kind == AdapterKind::Anthropic && request.stream {
        normalize_anthropic_stream(raw_stream)
    } else {
        raw_stream
    };
    Ok(ProviderDispatch {
        status_code: status,
        content_type,
        provider_request_id,
        stream,
    })
}

fn normalize_anthropic_stream(
    raw: LocalBoxStream<'static, Result<Vec<u8>, worker::Error>>,
) -> LocalBoxStream<'static, Result<Vec<u8>, worker::Error>> {
    stream::unfold(
        (raw, String::new(), false),
        |(mut raw, mut buffer, mut ended)| async move {
            loop {
                while let Some(boundary) = next_sse_boundary(&buffer) {
                    let event = buffer[..boundary].to_owned();
                    buffer.drain(..boundary + 2);
                    if let Some(output) = translate_anthropic_event(&event) {
                        return Some((Ok(output), (raw, buffer, ended)));
                    }
                }
                if ended {
                    return None;
                }
                match raw.next().await {
                    Some(Ok(chunk)) => {
                        buffer.push_str(&String::from_utf8_lossy(&chunk).replace("\r\n", "\n"));
                        if buffer.len() > 256 * 1024 {
                            return Some((
                                Err(worker::Error::RustError(
                                    "Anthropic SSE event exceeded the size limit".to_owned(),
                                )),
                                (raw, String::new(), true),
                            ));
                        }
                    }
                    Some(Err(error)) => {
                        return Some((Err(error), (raw, buffer, true)));
                    }
                    None => {
                        ended = true;
                        if buffer.trim().is_empty() {
                            return None;
                        }
                        let event = std::mem::take(&mut buffer);
                        if let Some(output) = translate_anthropic_event(&event) {
                            return Some((Ok(output), (raw, buffer, ended)));
                        }
                    }
                }
            }
        },
    )
    .boxed_local()
}

fn next_sse_boundary(buffer: &str) -> Option<usize> {
    buffer.find("\n\n")
}

fn translate_anthropic_event(event: &str) -> Option<Vec<u8>> {
    let data = event
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("\n");
    if data.is_empty() || data == "[DONE]" {
        return None;
    }
    let value = serde_json::from_str::<Value>(&data).ok()?;
    let id = value
        .get("message")
        .and_then(|message| message.get("id"))
        .and_then(Value::as_str)
        .unwrap_or("anthropic");
    let output = match value.get("type").and_then(Value::as_str) {
        Some("message_start") => json!({
            "id": id,
            "choices": [{"index": 0, "delta": {"role": "assistant"}}]
        }),
        Some("content_block_delta") => {
            let text = value
                .get("delta")
                .and_then(|delta| delta.get("text"))
                .and_then(Value::as_str)?;
            json!({
                "id": id,
                "choices": [{"index": 0, "delta": {"content": text}}]
            })
        }
        Some("message_delta") => {
            let usage = value.get("usage").cloned().unwrap_or_else(|| json!({}));
            json!({
                "id": id,
                "choices": [{"index": 0, "delta": {}}],
                "usage": {
                    "prompt_tokens": usage.get("input_tokens").and_then(Value::as_u64).unwrap_or(0),
                    "completion_tokens": usage.get("output_tokens").and_then(Value::as_u64).unwrap_or(0)
                }
            })
        }
        Some("message_stop") => return Some(b"data: [DONE]\n\n".to_vec()),
        Some("error") => json!({"error": {"code": "upstream_invalid_response"}}),
        _ => return None,
    };
    serde_json::to_vec(&output)
        .ok()
        .map(|value| [b"data: ".to_vec(), value, b"\n\n".to_vec()].concat())
}

fn mock_dispatch(
    endpoint: &str,
    provider_model_id: &str,
    request: &InferenceRequest,
) -> Result<ProviderDispatch, AdapterError> {
    if endpoint == "mock://lumi-timeout" || provider_model_id == "mock-timeout" {
        let stream = if request.stream {
            // A streaming cancellation fixture emits one complete event so
            // the response headers can be delivered, then remains pending.
            // The non-streaming path stays byte-silent for timeout coverage.
            let first = b"data: {\"id\":\"mock-timeout\",\"choices\":[{\"delta\":{\"content\":\"waiting\"}}]}\n\n";
            futures_util::stream::once(async { Ok::<Vec<u8>, worker::Error>(first.to_vec()) })
                .chain(futures_util::stream::pending::<
                    Result<Vec<u8>, worker::Error>,
                >())
                .boxed_local()
        } else {
            futures_util::stream::pending::<Result<Vec<u8>, worker::Error>>().boxed_local()
        };
        return Ok(ProviderDispatch {
            status_code: 200,
            content_type: Some(if request.stream {
                "text/event-stream".to_owned()
            } else {
                "application/json".to_owned()
            }),
            provider_request_id: Some("mock-timeout".to_owned()),
            stream,
        });
    }
    if endpoint == "mock://lumi-fail" || provider_model_id == "mock-fail" {
        return Err(AdapterError {
            kind: AdapterErrorKind::ConnectionFailed,
            retryable: true,
            status_code: None,
        });
    }
    let post_output_failure = endpoint == "mock://lumi-post-output-failure"
        || provider_model_id == "mock-post-output-failure";
    if endpoint != "mock://lumi-success"
        && provider_model_id != "mock-success"
        && !post_output_failure
    {
        return Err(invalid_request());
    }
    let first = if post_output_failure {
        "data: {\"id\":\"mock-post-output\",\"model\":\"mock-post-output-failure\",\"choices\":[{\"delta\":{\"content\":\"partial output\"}}]}\n\n"
    } else {
        "data: {\"id\":\"mock-request\",\"model\":\"mock-success\",\"choices\":[{\"delta\":{\"content\":\"Hello \"}}]}\n\n"
    };
    let metadata = "data: {\"id\":\"mock-request\",\"model\":\"mock-success\",\"choices\":[]}\n\n";
    let second = "data: {\"id\":\"mock-request\",\"model\":\"mock-success\",\"choices\":[{\"delta\":{\"content\":\"from Lumi.\"}}]}\n\n";
    let third = "data: {\"id\":\"mock-request\",\"model\":\"mock-success\",\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":3}}\n\ndata: [DONE]\n\n";
    let post_output_error = "data: {\"error\":{\"code\":\"synthetic_failure\",\"message\":\"post-output failure\"}}\n\n";
    let chunks = if post_output_failure {
        vec![
            Ok(metadata.as_bytes().to_vec()),
            Ok(first.as_bytes().to_vec()),
            Ok(post_output_error.as_bytes().to_vec()),
        ]
    } else if request.stream {
        vec![
            Ok(metadata.as_bytes().to_vec()),
            Ok(first.as_bytes().to_vec()),
            Ok(second.as_bytes().to_vec()),
            Ok(third.as_bytes().to_vec()),
        ]
    } else {
        vec![Ok(
            json!({
                "id": "mock-request",
                "model": "mock-success",
                "choices": [{"message": {"role": "assistant", "content": "Hello from Lumi."}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 4, "completion_tokens": 3}
            })
            .to_string()
            .into_bytes(),
        )]
    };
    Ok(ProviderDispatch {
        status_code: 200,
        content_type: Some(if request.stream {
            "text/event-stream".to_owned()
        } else {
            "application/json".to_owned()
        }),
        provider_request_id: Some(if post_output_failure {
            "mock-post-output".to_owned()
        } else {
            "mock-request".to_owned()
        }),
        stream: futures_util::stream::iter(chunks).boxed(),
    })
}

#[cfg(target_arch = "wasm32")]
fn timeout_signal(
    caller_signal: Option<&AbortSignal>,
    timeout_ms: u32,
) -> Result<AbortSignal, worker::Error> {
    use wasm_bindgen::prelude::wasm_bindgen;

    #[wasm_bindgen(inline_js = r#"
export function lumiInferenceTimeoutSignal(caller, timeoutMs) {
  const timeout = AbortSignal.timeout(timeoutMs);
  return caller ? AbortSignal.any([caller, timeout]) : timeout;
}
"#)]
    extern "C" {
        #[wasm_bindgen(js_name = lumiInferenceTimeoutSignal)]
        fn signal_js(
            caller: Option<&worker::web_sys::AbortSignal>,
            timeout_ms: u32,
        ) -> worker::web_sys::AbortSignal;
    }

    let caller = caller_signal.map(|signal| signal.as_ref());
    let result = signal_js(caller, timeout_ms);
    if result.is_null() {
        return Err(worker::Error::RustError(
            "provider timeout unavailable".to_owned(),
        ));
    }
    Ok(AbortSignal::from(result))
}

#[cfg(not(target_arch = "wasm32"))]
fn timeout_signal(
    _caller_signal: Option<&AbortSignal>,
    _timeout_ms: u32,
) -> Result<AbortSignal, worker::Error> {
    Err(worker::Error::RustError(
        "Worker timeout signal is unavailable in host tests".to_owned(),
    ))
}

/// Decode a provider stream into typed events. The caller owns the decoder so
/// it can preserve the response commitment boundary across network chunks.
pub fn decode_provider_stream(
    decoder: &mut SseDecoder,
    state: &mut crate::modules::inference::AdapterStreamState,
    chunk: &[u8],
) -> Vec<ProviderStreamEvent> {
    decoder.push(chunk, state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_validation_rejects_private_and_unlisted_destinations() {
        assert_eq!(
            validate_endpoint_url("http://127.0.0.1:8787", &[], false),
            Err(SsrfError::SchemeNotAllowed)
        );
        assert_eq!(
            validate_endpoint_url("https://127.0.0.1/v1", &[], false),
            Err(SsrfError::PrivateDestination)
        );
        assert_eq!(
            validate_endpoint_url("https://[::1]/v1", &[], false),
            Err(SsrfError::PrivateDestination)
        );
        assert_eq!(
            validate_endpoint_url("https://api.example.com/v1", &[], false),
            Err(SsrfError::HostNotAllowlisted)
        );
        assert!(
            validate_endpoint_url(
                "https://api.example.com/v1",
                &["api.example.com".to_owned()],
                false
            )
            .is_ok()
        );
    }

    #[test]
    fn anthropic_stream_events_are_normalized_without_provider_text_leakage() {
        let text = translate_anthropic_event(
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}",
        )
        .unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("hi"));
        assert!(text.starts_with("data: "));
        let done = translate_anthropic_event("data: {\"type\":\"message_stop\"}").unwrap();
        assert_eq!(done, b"data: [DONE]\n\n");
    }

    #[test]
    fn mock_fixture_streams_are_typed_and_deterministic() {
        let request = InferenceRequest {
            model: "coding-default".to_owned(),
            messages: vec![InferenceMessage::user("hello")],
            required_capabilities: Vec::new(),
            stream: true,
            max_output_tokens: None,
            temperature: None,
            tools: Vec::new(),
            retry_safe: true,
            project_id: None,
            session_id: None,
            run_id: None,
        };
        let dispatch = mock_dispatch("mock://lumi-success", "mock-success", &request).unwrap();
        assert_eq!(dispatch.status_code, 200);
        assert_eq!(
            dispatch.provider_request_id.as_deref(),
            Some("mock-request")
        );
        assert_eq!(dispatch.content_type.as_deref(), Some("text/event-stream"));
    }
}
