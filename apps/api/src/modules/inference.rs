//! P04 vendor-neutral inference envelopes and response safety state machine.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::catalog::ModelCapability;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentPart {
    Text { text: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceMessage {
    pub role: MessageRole,
    pub content: Vec<ContentPart>,
}

impl InferenceMessage {
    pub fn user(text: impl Into<String>) -> Self {
        Self {
            role: MessageRole::User,
            content: vec![ContentPart::Text { text: text.into() }],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InferenceRequest {
    pub model: String,
    pub messages: Vec<InferenceMessage>,
    pub required_capabilities: Vec<ModelCapability>,
    pub stream: bool,
    pub max_output_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub tools: Vec<Value>,
    pub project_id: Option<String>,
    pub session_id: Option<String>,
    pub run_id: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseLifecycle {
    NotDispatched,
    DispatchedNoOutput,
    StreamCommitted,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterErrorKind {
    ConnectionFailed,
    Timeout,
    RateLimited,
    ProviderUnavailable,
    InvalidRequest,
    InvalidResponse,
    CredentialRejected,
    UnsupportedCapability,
    ContentFiltered,
}

impl AdapterErrorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionFailed => "connection_failed",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidResponse => "invalid_response",
            Self::CredentialRejected => "credential_rejected",
            Self::UnsupportedCapability => "unsupported_capability",
            Self::ContentFiltered => "content_filtered",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterError {
    pub kind: AdapterErrorKind,
    pub retryable: bool,
    pub status_code: Option<u16>,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind.as_str())
    }
}

pub fn normalize_adapter_error(status_code: u16, _upstream_body: &str) -> AdapterError {
    let kind = match status_code {
        408 | 504 => AdapterErrorKind::Timeout,
        429 => AdapterErrorKind::RateLimited,
        401 | 403 => AdapterErrorKind::CredentialRejected,
        400 | 422 => AdapterErrorKind::InvalidRequest,
        502 | 503 => AdapterErrorKind::ProviderUnavailable,
        _ => AdapterErrorKind::InvalidResponse,
    };
    AdapterError {
        kind,
        retryable: matches!(
            kind,
            AdapterErrorKind::ConnectionFailed
                | AdapterErrorKind::Timeout
                | AdapterErrorKind::RateLimited
                | AdapterErrorKind::ProviderUnavailable
        ),
        status_code: Some(status_code),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProviderUsage {
    pub input_tokens: Option<u32>,
    pub output_tokens: Option<u32>,
    pub cached_tokens: Option<u32>,
    pub provider_name: Option<String>,
    pub pricing_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderStreamEvent {
    TextDelta { text: String },
    ToolCallDelta { call_id: String, arguments_delta: String },
    Usage { usage: ProviderUsage },
    ProviderRequestId { provider_request_id: String },
    Done,
    InvalidResponse,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdapterStreamState {
    pub done: bool,
    pub invalid_response: bool,
    pub buffer_bytes: usize,
}

#[derive(Clone, Debug, Default)]
pub struct SseDecoder {
    buffer: String,
}

impl SseDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode complete SSE events while retaining a bounded partial event for
    /// the next network chunk. Malformed provider data is represented as a
    /// typed event and never forwarded as a raw body.
    pub fn push(&mut self, bytes: &[u8], state: &mut AdapterStreamState) -> Vec<ProviderStreamEvent> {
        if state.done || bytes.len() > 256 * 1024 {
            state.invalid_response = true;
            return vec![ProviderStreamEvent::InvalidResponse];
        }
        let text = String::from_utf8_lossy(bytes);
        self.buffer.push_str(&text);
        state.buffer_bytes = self.buffer.len();
        if self.buffer.len() > 512 * 1024 {
            self.buffer.clear();
            state.invalid_response = true;
            return vec![ProviderStreamEvent::InvalidResponse];
        }
        let normalized = self.buffer.replace("\r\n", "\n").replace('\r', "\n");
        let Some(separator_end) = normalized.rfind("\n\n") else {
            state.buffer_bytes = normalized.len();
            self.buffer = normalized;
            return Vec::new();
        };
        let complete = &normalized[..separator_end + 2];
        let remaining = normalized[separator_end + 2..].to_owned();
        let mut events = Vec::new();
        for block in complete.split("\n\n") {
            if block.trim().is_empty() {
                continue;
            }
            if !block.contains("data:") {
                state.invalid_response = true;
                events.push(ProviderStreamEvent::InvalidResponse);
                continue;
            }
            let mut data = String::new();
            for line in block.lines() {
                if let Some(value) = line.strip_prefix("data:") {
                    if !data.is_empty() {
                        data.push('\n');
                    }
                    data.push_str(value.trim_start());
                }
            }
            if data == "[DONE]" {
                state.done = true;
                events.push(ProviderStreamEvent::Done);
                continue;
            }
            match serde_json::from_str::<Value>(&data) {
                Ok(value) => events.extend(decode_openai_value(&value, state)),
                Err(_) => {
                    state.invalid_response = true;
                    events.push(ProviderStreamEvent::InvalidResponse);
                }
            }
        }
        self.buffer = remaining;
        state.buffer_bytes = self.buffer.len();
        events
    }

    pub fn finish(&mut self, state: &mut AdapterStreamState) -> Vec<ProviderStreamEvent> {
        if self.buffer.trim().is_empty() {
            return Vec::new();
        }
        let bytes = self.buffer.as_bytes().to_vec();
        self.buffer.clear();
        self.push(&bytes, state)
    }
}

fn decode_openai_value(value: &Value, state: &mut AdapterStreamState) -> Vec<ProviderStreamEvent> {
    let mut events = Vec::new();
    if let Some(id) = value.get("id").and_then(Value::as_str)
        && !id.is_empty()
    {
        events.push(ProviderStreamEvent::ProviderRequestId {
            provider_request_id: id.to_owned(),
        });
    }
    if let Some(usage) = value.get("usage").filter(|usage| !usage.is_null()) {
        events.push(ProviderStreamEvent::Usage {
            usage: ProviderUsage {
                input_tokens: usage.get("prompt_tokens").and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok()),
                output_tokens: usage.get("completion_tokens").and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok()),
                cached_tokens: usage
                    .get("prompt_tokens_details")
                    .and_then(|details| details.get("cached_tokens"))
                    .and_then(Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok()),
                provider_name: value.get("model").and_then(Value::as_str).map(str::to_owned),
                pricing_version: None,
            },
        });
    }
    let Some(choice) = value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
    else {
        return events;
    };
    if let Some(text) = choice
        .get("delta")
        .and_then(|delta| delta.get("content"))
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    {
        events.push(ProviderStreamEvent::TextDelta {
            text: text.to_owned(),
        });
    }
    if let Some(tool_calls) = choice
        .get("delta")
        .and_then(|delta| delta.get("tool_calls"))
        .and_then(Value::as_array)
    {
        for call in tool_calls {
            let call_id = call
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("tool_call")
                .to_owned();
            let arguments_delta = call
                .get("function")
                .and_then(|function| function.get("arguments"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            events.push(ProviderStreamEvent::ToolCallDelta {
                call_id,
                arguments_delta,
            });
        }
    }
    if events.is_empty() {
        state.invalid_response = true;
        events.push(ProviderStreamEvent::InvalidResponse);
    }
    events
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryController {
    state: ResponseLifecycle,
    remaining_retries: u8,
    max_fallbacks: u8,
    fallback_count: u8,
}

impl RetryController {
    pub fn new(remaining_retries: u8, max_fallbacks: u8) -> Self {
        Self {
            state: ResponseLifecycle::NotDispatched,
            remaining_retries,
            max_fallbacks,
            fallback_count: 0,
        }
    }

    pub fn state(&self) -> ResponseLifecycle {
        self.state
    }

    pub fn fallback_count(&self) -> u8 {
        self.fallback_count
    }

    pub fn can_retry(&self) -> bool {
        matches!(
            self.state,
            ResponseLifecycle::NotDispatched | ResponseLifecycle::DispatchedNoOutput
        ) && (self.remaining_retries > 0 || self.fallback_count < self.max_fallbacks)
    }

    pub fn mark_dispatched(&mut self) {
        if matches!(self.state, ResponseLifecycle::NotDispatched) {
            self.state = ResponseLifecycle::DispatchedNoOutput;
        }
    }

    pub fn mark_stream_committed(&mut self) {
        if matches!(
            self.state,
            ResponseLifecycle::NotDispatched | ResponseLifecycle::DispatchedNoOutput
        ) {
            self.state = ResponseLifecycle::StreamCommitted;
        }
    }

    pub fn mark_retryable_failure(&mut self, _kind: AdapterErrorKind) {
        if self.state == ResponseLifecycle::StreamCommitted {
            self.state = ResponseLifecycle::Failed;
            return;
        }
        if self.can_retry() {
            self.remaining_retries = self.remaining_retries.saturating_sub(1);
            self.fallback_count = self.fallback_count.saturating_add(1);
            self.state = ResponseLifecycle::NotDispatched;
        } else {
            self.state = ResponseLifecycle::Failed;
        }
    }

    pub fn complete(&mut self) {
        self.state = ResponseLifecycle::Completed;
    }

    pub fn fail(&mut self) {
        self.state = ResponseLifecycle::Failed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_sse_event_is_retained_until_complete() {
        let mut decoder = SseDecoder::new();
        let mut state = AdapterStreamState::default();
        assert!(decoder.push(b"data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}", &mut state).is_empty());
        let events = decoder.push(b"\n\n", &mut state);
        assert!(matches!(events.as_slice(), [ProviderStreamEvent::TextDelta { .. }]));
    }

    #[test]
    fn adapter_error_display_never_contains_upstream_body() {
        let error = normalize_adapter_error(503, "secret body");
        assert_eq!(error.to_string(), "provider_unavailable");
    }
}
