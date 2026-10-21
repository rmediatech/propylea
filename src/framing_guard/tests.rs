//! # Unit Tests for Sovereign HTTP Framing Guard (`framing_guard/tests.rs`)

use super::*;
use hyper::header::HeaderValue;

#[test]
fn test_rejects_conflicting_content_length_and_transfer_encoding() {
    let guard = FramingGuard::default();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("42"));
    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));

    let res = guard.validate_headers(&headers, &Method::POST);
    assert_eq!(res, Err(FramingViolation::ConflictingFraming));
}

#[test]
fn test_rejects_multiple_differing_content_lengths() {
    let guard = FramingGuard::default();
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_LENGTH, HeaderValue::from_static("42"));
    headers.append(CONTENT_LENGTH, HeaderValue::from_static("99"));

    let res = guard.validate_headers(&headers, &Method::POST);
    assert_eq!(res, Err(FramingViolation::MultipleContentLengths));
}

#[test]
fn test_allows_multiple_identical_content_lengths() {
    let guard = FramingGuard::default();
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_LENGTH, HeaderValue::from_static("42"));
    headers.append(CONTENT_LENGTH, HeaderValue::from_static("42"));

    let res = guard.validate_headers(&headers, &Method::POST);
    assert!(res.is_ok());
}

#[test]
fn test_rejects_comma_separated_differing_content_lengths() {
    let guard = FramingGuard::default();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("42, 99"));

    let res = guard.validate_headers(&headers, &Method::POST);
    assert_eq!(res, Err(FramingViolation::MultipleContentLengths));
}

#[test]
fn test_rejects_illegal_control_char_and_ansi_esc_in_header() {
    let res = FramingGuard::check_header_value_bytes("X-Malicious", b"admin\0spoof");
    assert_eq!(
        res,
        Err(FramingViolation::IllegalHeaderCharacter(
            "X-Malicious".into()
        ))
    );

    let res_del = FramingGuard::check_header_value_bytes("X-Malicious", b"admin\x7fspoof");
    assert_eq!(
        res_del,
        Err(FramingViolation::IllegalHeaderCharacter(
            "X-Malicious".into()
        ))
    );

    let res_esc = FramingGuard::check_header_value_bytes("User-Agent", b"Bot\x1b[31mRed");
    assert_eq!(
        res_esc,
        Err(FramingViolation::IllegalHeaderCharacter(
            "User-Agent".into()
        ))
    );

    let res_clean =
        FramingGuard::check_header_value_bytes("X-Clean", b"admin-standard-token_123");
    assert!(res_clean.is_ok());
}

#[test]
fn test_rejects_payload_exceeding_max_limit() {
    let guard = FramingGuard::new(1024);
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("2048"));

    let res = guard.validate_headers(&headers, &Method::POST);
    assert_eq!(
        res,
        Err(FramingViolation::PayloadTooLarge {
            limit: 1024,
            requested: 2048
        })
    );
}

#[test]
fn test_rejects_unsupported_transfer_encoding() {
    let guard = FramingGuard::default();
    let mut headers = HeaderMap::new();
    headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("gzip"));

    let res = guard.validate_headers(&headers, &Method::POST);
    assert!(matches!(
        res,
        Err(FramingViolation::UnsupportedTransferEncoding(_))
    ));
}

#[test]
fn test_rejects_get_with_positive_content_length() {
    let guard = FramingGuard::default();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("50"));

    let res = guard.validate_headers(&headers, &Method::GET);
    assert!(matches!(
        res,
        Err(FramingViolation::MalformedContentLength(_))
    ));
}

#[test]
fn test_sanitizes_untrusted_ingress_headers() {
    let mut req = Request::builder()
        .header("X-Forwarded-For", "1.2.3.4")
        .header("X-Real-IP", "5.6.7.8")
        .body(())
        .unwrap();

    let client_ip: IpAddr = "198.51.100.99".parse().unwrap();
    FramingGuard::sanitize_ingress_headers(&mut req, client_ip);

    assert_eq!(
        req.headers()
            .get("X-Forwarded-For")
            .unwrap()
            .to_str()
            .unwrap(),
        "198.51.100.99"
    );
    assert_eq!(
        req.headers().get("X-Real-IP").unwrap().to_str().unwrap(),
        "198.51.100.99"
    );
    assert_eq!(
        req.headers()
            .get("X-Forwarded-Proto")
            .unwrap()
            .to_str()
            .unwrap(),
        "https"
    );
}
