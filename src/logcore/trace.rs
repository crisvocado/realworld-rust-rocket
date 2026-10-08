use crate::logcore::models::TraceInfo;

/// Parses a W3C traceparent header:
/// Format: {version}-{trace_id}-{parent_id/span_id}-{trace_flags}
/// e.g. "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
pub fn parse_traceparent(header: &str) -> Option<TraceInfo> {
    let parts: Vec<&str> = header.trim().split('-').collect();
    if parts.len() < 4 {
        return None;
    }

    let trace_id = parts[1];
    let span_id = parts[2];
    let flags_str = parts[3];

    // trace_id must be 32 lowercase hex characters and non-zero
    if trace_id.len() != 32 || !trace_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if trace_id == "00000000000000000000000000000000" {
        return None;
    }

    let span_id_opt = if span_id.len() == 16
        && span_id.chars().all(|c| c.is_ascii_hexdigit())
        && span_id != "0000000000000000"
    {
        Some(span_id.to_string())
    } else {
        None
    };

    let sampled = u8::from_str_radix(flags_str, 16)
        .map(|f| (f & 0x01) != 0)
        .unwrap_or(false);

    Some(TraceInfo {
        trace_id: trace_id.to_lowercase(),
        span_id: span_id_opt.map(|s| s.to_lowercase()),
        sampled: Some(sampled),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_traceparent() {
        let header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let trace = parse_traceparent(header).expect("should parse");
        assert_eq!(trace.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(trace.span_id.as_deref(), Some("00f067aa0ba902b7"));
        assert_eq!(trace.sampled, Some(true));
    }

    #[test]
    fn test_invalid_traceparent() {
        assert!(parse_traceparent("").is_none());
        assert!(parse_traceparent("invalid").is_none());
        assert!(parse_traceparent("00-00000000000000000000000000000000-0000000000000000-00").is_none());
    }
}
