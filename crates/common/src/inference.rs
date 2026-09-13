//! Exact-action inference mediation shared by the Phase-1 gateway/hostd and Linux eval host.
//!
//! The caller owns endpoint admission, lease/gate dispatch and response fences, cancellation,
//! concurrency, and transport limits. This module preserves the Phase-1 combined validation and
//! fresh native `/api/chat` request construction; client JSON is never forwarded to the backend.

use crate::{sha256_hex, MAX_MSG_BYTES};
use serde_json::{json, Value};

/// Validate the one bounded, model-pinned chat operation. Message validation also runs here so
/// both gateway implementations enforce the complete trusted hostd contract before dispatch.
pub fn validate(model: &str, body: &[u8]) -> Result<Value, &'static str> {
    if body.len() > MAX_MSG_BYTES {
        return Err("body too large");
    }
    let v: Value = serde_json::from_slice(body).map_err(|_| "not json")?;
    let o = v.as_object().ok_or("not an object")?;
    if o.get("model").and_then(|m| m.as_str()) != Some(model) {
        return Err("model not pinned");
    }
    for k in [
        "tools",
        "functions",
        "tool_choice",
        "function_call",
        "response_format",
    ] {
        if o.contains_key(k) {
            return Err("tool/function fields not allowed");
        }
    }
    // Reject wrong types as well as unbounded values. The old gateway treated e.g. stream:"true"
    // or n:-1 as omitted; the native backend always received false/one, but these are not valid
    // descriptions of the exact permitted action.
    if o.get("stream").is_some_and(|s| s.as_bool() != Some(false)) {
        return Err("stream must be false");
    }
    if o.get("n").is_some_and(|n| n.as_u64() != Some(1)) {
        return Err("n must be 1");
    }
    // In particular, -1 must not become an unlimited backend generation request.
    if let Some(mt) = o.get("max_tokens") {
        match mt.as_u64() {
            Some(n) if n <= 1024 => {}
            _ => return Err("max_tokens must be an integer in [0,1024]"),
        }
    }
    let messages = o
        .get("messages")
        .and_then(|m| m.as_array())
        .filter(|a| !a.is_empty())
        .ok_or("messages required")?;
    for message in messages {
        match (
            message.get("role").and_then(|r| r.as_str()),
            message.get("content").and_then(|c| c.as_str()),
        ) {
            (Some("system" | "user" | "assistant" | "tool"), Some(_)) => {}
            _ => return Err("each message must be {role, content:string} with a known role"),
        }
    }
    Ok(v)
}

/// Construct a FRESH request with only the Phase-1 allowlist. Ollama's Go decoder case-folds
/// names (e.g. `max_tokenſ` → `max_tokens`), so preserving client fields could reset a generation
/// cap. Native `/api/chat` honors `options.num_ctx`/`num_predict`; the OpenAI-compatible endpoint
/// ignores `options`. Unknown top-level and message fields are discarded, as in Phase-1 hostd.
pub fn backend_request(model: &str, body: &[u8]) -> Result<Value, &'static str> {
    let value = validate(model, body)?;
    let max_tokens = value
        .get("max_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(512);
    let messages: Vec<Value> = value["messages"]
        .as_array()
        .expect("validated messages")
        .iter()
        .map(|message| json!({"role": message["role"], "content": message["content"]}))
        .collect();
    Ok(json!({
        "model": model,
        "messages": messages,
        "stream": false,
        "options": {"num_ctx": 4096, "num_predict": max_tokens},
    }))
}

/// Map the native response to the same OpenAI chat.completion shape used by the Phase-1 harness.
/// Call only after the caller's final response authority fence.
pub fn map_response(model: &str, body: &[u8], native: &Value) -> Value {
    let content = native
        .pointer("/message/content")
        .and_then(Value::as_str)
        .unwrap_or("");
    json!({
        "id": format!("chatcmpl-{}", &sha256_hex(body)[..24]),
        "object": "chat.completion",
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": native.get("done_reason").and_then(Value::as_str).unwrap_or("stop")}],
        "usage": {"prompt_tokens": native.get("prompt_eval_count").and_then(Value::as_u64).unwrap_or(0), "completion_tokens": native.get("eval_count").and_then(Value::as_u64).unwrap_or(0)}
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &[u8] = br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;

    fn request_with(key: &str, value: Value) -> Vec<u8> {
        let mut request: Value = serde_json::from_slice(VALID).unwrap();
        request[key] = value;
        serde_json::to_vec(&request).unwrap()
    }

    #[test]
    fn only_a_model_pinned_json_object_is_accepted() {
        assert!(validate("m", VALID).is_ok());
        assert_eq!(validate("other", VALID).unwrap_err(), "model not pinned");
        assert_eq!(validate("m", b"GET / HTTP/1.1").unwrap_err(), "not json");
        for body in [b"[]".as_slice(), b"null", b"42"] {
            assert_eq!(validate("m", body).unwrap_err(), "not an object");
        }
        for model in [Value::Null, json!(42), json!("M")] {
            assert_eq!(
                validate("m", &request_with("model", model)).unwrap_err(),
                "model not pinned"
            );
        }
    }

    #[test]
    fn request_size_is_bounded_in_bytes() {
        let mut body = VALID.to_vec();
        body.resize(MAX_MSG_BYTES, b' ');
        assert!(backend_request("m", &body).is_ok());
        body.push(b' ');
        assert_eq!(backend_request("m", &body).unwrap_err(), "body too large");
        let body = request_with(
            "messages",
            json!([{"role": "user", "content": "🛑".repeat(MAX_MSG_BYTES / 4)}]),
        );
        assert_eq!(validate("m", &body).unwrap_err(), "body too large");
    }

    #[test]
    fn all_tool_and_function_fields_are_denied_even_when_empty() {
        for key in [
            "tools",
            "functions",
            "tool_choice",
            "function_call",
            "response_format",
        ] {
            for value in [Value::Null, json!([]), json!({})] {
                assert_eq!(
                    backend_request("m", &request_with(key, value)).unwrap_err(),
                    "tool/function fields not allowed",
                    "{key}"
                );
            }
        }
    }

    #[test]
    fn streaming_and_multiple_operations_cannot_validate_through_wrong_types() {
        assert!(validate("m", &request_with("stream", json!(false))).is_ok());
        assert!(validate("m", &request_with("n", json!(1))).is_ok());
        for value in [
            Value::Null,
            json!(true),
            json!("false"),
            json!(0),
            json!({}),
        ] {
            assert_eq!(
                validate("m", &request_with("stream", value)).unwrap_err(),
                "stream must be false"
            );
        }
        for value in [
            Value::Null,
            json!(-1),
            json!(0),
            json!(2),
            json!(1.0),
            json!("1"),
            json!(true),
        ] {
            assert_eq!(
                validate("m", &request_with("n", value)).unwrap_err(),
                "n must be 1"
            );
        }
    }

    #[test]
    fn generation_bound_rejects_unlimited_and_invalid_sizes() {
        for value in [
            Value::Null,
            json!(-1),
            json!(1025),
            json!(4096),
            json!(u64::MAX),
            json!(1.5),
            json!("512"),
            json!(false),
        ] {
            assert_eq!(
                backend_request("m", &request_with("max_tokens", value)).unwrap_err(),
                "max_tokens must be an integer in [0,1024]"
            );
        }
        for tokens in [0, 1, 512, 1024] {
            let backend = backend_request("m", &request_with("max_tokens", json!(tokens))).unwrap();
            assert_eq!(
                backend["options"],
                json!({"num_ctx": 4096, "num_predict": tokens})
            );
        }
        assert_eq!(
            backend_request("m", VALID).unwrap()["options"],
            json!({"num_ctx": 4096, "num_predict": 512})
        );
    }

    #[test]
    fn only_known_roles_and_string_content_are_valid_messages() {
        for role in ["system", "user", "assistant", "tool"] {
            assert!(validate(
                "m",
                &request_with("messages", json!([{"role": role, "content": ""}]))
            )
            .is_ok());
        }
        for messages in [Value::Null, json!([]), json!({}), json!("hi")] {
            assert_eq!(
                validate("m", &request_with("messages", messages)).unwrap_err(),
                "messages required"
            );
        }
        for message in [
            Value::Null,
            json!("hi"),
            json!({"role": "unknown", "content": "hi"}),
            json!({"role": "user"}),
            json!({"content": "hi"}),
            json!({"role": "user", "content": []}),
            json!({"role": "user", "content": 1}),
        ] {
            assert_eq!(
                backend_request("m", &request_with("messages", json!([message]))).unwrap_err(),
                "each message must be {role, content:string} with a known role"
            );
        }
    }

    #[test]
    fn fresh_backend_request_strips_cap_bypass_and_message_extension_fields() {
        let body = serde_json::to_vec(&json!({
            "model": "m",
            "MODEL": "unapproved",
            "messages": [{"role": "user", "content": "hi", "images": ["hidden"], "tool_calls": ["hidden"], "CONTENT": "hidden"}],
            "stream": false,
            "STREAM": true,
            "n": 1,
            "max_tokens": 16,
            "max_tokenſ": -1,
            "MAX_TOKENS": -1,
            "options": {"num_ctx": -1, "num_predict": -1},
            "optionſ": {"num_predict": -1},
            "keep_alive": -1,
            "TOOLS": ["hidden"],
            "toolſ": ["hidden"],
        })).unwrap();
        assert_eq!(
            backend_request("m", &body).unwrap(),
            json!({
                "model": "m", "messages": [{"role": "user", "content": "hi"}], "stream": false,
                "options": {"num_ctx": 4096, "num_predict": 16},
            })
        );
    }

    #[test]
    fn response_mapping_matches_phase1_and_ignores_backend_extensions() {
        let native = json!({
            "model": "backend-supplied-model", "message": {"role": "tool", "content": "answer", "tool_calls": ["hidden"]},
            "done_reason": "length", "prompt_eval_count": 5, "eval_count": 7, "extra": "hidden",
        });
        assert_eq!(
            map_response("m", VALID, &native),
            json!({
                "id": format!("chatcmpl-{}", &sha256_hex(VALID)[..24]), "object": "chat.completion", "model": "m",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "answer"}, "finish_reason": "length"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 7},
            })
        );
        for native in [
            Value::Null,
            json!({"error": "bad upstream body"}),
            json!({"message": {"content": []}, "done_reason": 1, "prompt_eval_count": -1, "eval_count": "7"}),
        ] {
            let mapped = map_response("m", VALID, &native);
            assert_eq!(
                mapped["choices"],
                json!([{"index": 0, "message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}])
            );
            assert_eq!(
                mapped["usage"],
                json!({"prompt_tokens": 0, "completion_tokens": 0})
            );
        }
    }
}
