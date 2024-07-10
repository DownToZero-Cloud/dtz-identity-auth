use super::*;
use jwt_simple::{
    prelude::{NoCustomClaims, RS256PublicKey, RSAPublicKeyLike},
    reexports::ct_codecs,
};
use serde_json::Value;
use uuid::Uuid;
#[test]
fn test_replacement_identity() {
    let identity = DtzProfile {
        identity_id: IdentityId {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
        },
        context_id: ContextId {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
        },
        roles: vec!["admin".to_string()],
        token: "".to_string(),
    };
    let result =
        super::replace_placeholder("https://dtz.rocks/context/admin/{identity_id}", &identity);
    assert_eq!(
        result,
        "https://dtz.rocks/context/admin/00000000-0000-0000-0000-000000000000"
    );
}
#[test]
fn test_replacement_context() {
    let identity = DtzProfile {
        identity_id: IdentityId {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
        },
        context_id: ContextId {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
        },
        roles: vec!["admin".to_string()],
        token: "".to_string(),
    };
    let result =
        super::replace_placeholder("https://dtz.rocks/context/admin/{context_id}", &identity);
    assert_eq!(
        result,
        "https://dtz.rocks/context/admin/00000000-0000-0000-0000-000000000000"
    );
}
#[test]
fn test_replacement_nothing() {
    let identity = DtzProfile {
        identity_id: IdentityId {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
        },
        context_id: ContextId {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
        },
        roles: vec!["admin".to_string()],
        token: "".to_string(),
    };
    let result = super::replace_placeholder("https://dtz.rocks/context/admin", &identity);
    assert_eq!(result, "https://dtz.rocks/context/admin");
}

#[test]
fn parse_public_key() {
    let public_key = RS256PublicKey::from_pem(PUBLIC_KEY).unwrap();
    println!("{public_key:?}");
}

#[test]
fn verify_token() {
    let public_key = RS256PublicKey::from_pem(PUBLIC_KEY).unwrap();
    let token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImR0ejEifQ.eyJpc3MiOiJkdHoucm9ja3MiLCJzdWIiOiIwZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJhdWQiOiJkdHoucm9ja3MiLCJzY29wZSI6IjNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsInJvbGVzIjpbImh0dHBzOi8vZHR6LnJvY2tzL2Zsb3dzL2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL29ic2VydmFiaWxpdHkvYWRtaW4vM2NkODQ0MjktNjRhNC00MjI2LWI4NjgtYzgzZmVlZmYwZjQ2IiwiaHR0cHM6Ly9kdHoucm9ja3Mvb2JzZXJ2YWJpbGl0eS9hZG1pbi9kM2UxNDQyMi03YWJjLTQzMGQtYmU0OS1kNDNlY2RiMjVhYTYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hZG1pbi83OWU2ZmJmZS1kYTFmLTRjMzgtOGE5Ny00M2U4NDlmYzk4ZWEiLCJodHRwczovL2R0ei5yb2Nrcy9vYnNlcnZhYmlsaXR5L2FkbWluLzc5ZTZmYmZlLWRhMWYtNGMzOC04YTk3LTQzZTg0OWZjOThlYSIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluL2Q2Y2FmMTdhLWUyN2ItNDcwOC1hMTcxLTg2OTBkOGYxMmFmZSIsImh0dHBzOi8vZHR6LnJvY2tzL2NvbnRhaW5lcnMvYWRtaW4vM2NkODQ0MjktNjRhNC00MjI2LWI4NjgtYzgzZmVlZmYwZjQ2IiwiaHR0cHM6Ly9kdHoucm9ja3MvaWRlbnRpdHkvYXNzdW1lLzBlNGRhYzI0LWRkMjMtNDY1NS1hNDcxLTUyNjUzYTEwZDE1ZiIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2Fzc3VtZS8zZmY2MGMzZC1hOTJlLTRhNmEtYjFlYS1hMjhmMmEzNmI0MTYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hc3N1bWUvZGQzYTZkYzAtODZkZi00YTNhLWFiYzQtZTMzMGU0MWNkMjVhIiwiaHR0cHM6Ly9kdHoucm9ja3MvYmlsbGluZy9hZG1pbi8wZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hZG1pbi8wZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJodHRwczovL2R0ei5yb2Nrcy9jb250ZXh0L2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL2NvbnRleHQvYWRtaW4vZDZjYWYxN2EtZTI3Yi00NzA4LWExNzEtODY5MGQ4ZjEyYWZlIiwiaHR0cHM6Ly9kdHoucm9ja3MvY29udGFpbmVycy9hZG1pbi9kNmNhZjE3YS1lMjdiLTQ3MDgtYTE3MS04NjkwZDhmMTJhZmUiXSwiZXhwIjoxNjgwODUzMzY1LCJpYXQiOjE2ODA3NjY5NjV9.ACZ1x_L32jZj7iWZjarhuLssKkfOzkZbcToSVe9FEL8Y7iBo1Hlo8XIg26mq7dqDJCJhtS0KQAWDZq4rXq_nu0tiUWmL6ZlX3A0HlWjxBH1kbcwc4sMVbj3-k0Z7n3aTK_LH0hcoImYt7nBcV0naK4ZrLrPvSTWuOEw7TNCeh1kJitheXUvWxvBLG-1iK9QEDIVuRZk0KvhBajA2LM5DxnFw1nBVV6Ih8Maw_gU74s24VdhtsLievom4u_PR-CeeMR11Y1Xi9n7TrcAKH3RaeNIWDEuXcR-RFg99kUArcvVS12Bbkc7gf0MPo-APB_csOOppbSJ9yXUHghsIRYN3xg";
    let claims = public_key.verify_token::<NoCustomClaims>(&token, None);
    println!("{claims:?}");
    // is expired
    assert!(claims.is_err());
    // assert!(claims.is_ok());
    // println!("{:?}", claims.ok().unwrap());
}

#[test]
fn claims_decode() {
    use ct_codecs::{Base64UrlSafe, Decoder};
    let encoded = "eyJpc3MiOiJkdHoucm9ja3MiLCJzdWIiOiIwZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJhdWQiOiJkdHoucm9ja3MiLCJzY29wZSI6IjNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsInJvbGVzIjpbImh0dHBzOi8vZHR6LnJvY2tzL2Zsb3dzL2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL29ic2VydmFiaWxpdHkvYWRtaW4vM2NkODQ0MjktNjRhNC00MjI2LWI4NjgtYzgzZmVlZmYwZjQ2IiwiaHR0cHM6Ly9kdHoucm9ja3Mvb2JzZXJ2YWJpbGl0eS9hZG1pbi9kM2UxNDQyMi03YWJjLTQzMGQtYmU0OS1kNDNlY2RiMjVhYTYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hZG1pbi83OWU2ZmJmZS1kYTFmLTRjMzgtOGE5Ny00M2U4NDlmYzk4ZWEiLCJodHRwczovL2R0ei5yb2Nrcy9vYnNlcnZhYmlsaXR5L2FkbWluLzc5ZTZmYmZlLWRhMWYtNGMzOC04YTk3LTQzZTg0OWZjOThlYSIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluL2Q2Y2FmMTdhLWUyN2ItNDcwOC1hMTcxLTg2OTBkOGYxMmFmZSIsImh0dHBzOi8vZHR6LnJvY2tzL2NvbnRhaW5lcnMvYWRtaW4vM2NkODQ0MjktNjRhNC00MjI2LWI4NjgtYzgzZmVlZmYwZjQ2IiwiaHR0cHM6Ly9kdHoucm9ja3MvaWRlbnRpdHkvYXNzdW1lLzBlNGRhYzI0LWRkMjMtNDY1NS1hNDcxLTUyNjUzYTEwZDE1ZiIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2Fzc3VtZS8zZmY2MGMzZC1hOTJlLTRhNmEtYjFlYS1hMjhmMmEzNmI0MTYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hc3N1bWUvZGQzYTZkYzAtODZkZi00YTNhLWFiYzQtZTMzMGU0MWNkMjVhIiwiaHR0cHM6Ly9kdHoucm9ja3MvYmlsbGluZy9hZG1pbi8wZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hZG1pbi8wZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJodHRwczovL2R0ei5yb2Nrcy9jb250ZXh0L2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL2NvbnRleHQvYWRtaW4vZDZjYWYxN2EtZTI3Yi00NzA4LWExNzEtODY5MGQ4ZjEyYWZlIiwiaHR0cHM6Ly9kdHoucm9ja3MvY29udGFpbmVycy9hZG1pbi9kNmNhZjE3YS1lMjdiLTQ3MDgtYTE3MS04NjkwZDhmMTJhZmUiXSwiZXhwIjoxNjgwODUzMzY1LCJpYXQiOjE2ODA3NjY5NjV9";
    let decoded = Base64UrlSafe::decode_to_vec(encoded, None).unwrap();
    let json_str = String::from_utf8_lossy(&decoded);
    let json: Value = serde_json::de::from_str(&json_str).unwrap();
    let roles = json.get("roles").unwrap().as_array().unwrap();
    println!("{:?}", roles);
}

#[test]
fn claims_decode_scope() {
    use ct_codecs::{Base64UrlSafe, Decoder};
    let encoded = "eyJpc3MiOiJkdHoucm9ja3MiLCJzdWIiOiIwZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJhdWQiOiJkdHoucm9ja3MiLCJzY29wZSI6IjNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsInJvbGVzIjpbImh0dHBzOi8vZHR6LnJvY2tzL2Zsb3dzL2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL29ic2VydmFiaWxpdHkvYWRtaW4vM2NkODQ0MjktNjRhNC00MjI2LWI4NjgtYzgzZmVlZmYwZjQ2IiwiaHR0cHM6Ly9kdHoucm9ja3Mvb2JzZXJ2YWJpbGl0eS9hZG1pbi9kM2UxNDQyMi03YWJjLTQzMGQtYmU0OS1kNDNlY2RiMjVhYTYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hZG1pbi83OWU2ZmJmZS1kYTFmLTRjMzgtOGE5Ny00M2U4NDlmYzk4ZWEiLCJodHRwczovL2R0ei5yb2Nrcy9vYnNlcnZhYmlsaXR5L2FkbWluLzc5ZTZmYmZlLWRhMWYtNGMzOC04YTk3LTQzZTg0OWZjOThlYSIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluL2Q2Y2FmMTdhLWUyN2ItNDcwOC1hMTcxLTg2OTBkOGYxMmFmZSIsImh0dHBzOi8vZHR6LnJvY2tzL2NvbnRhaW5lcnMvYWRtaW4vM2NkODQ0MjktNjRhNC00MjI2LWI4NjgtYzgzZmVlZmYwZjQ2IiwiaHR0cHM6Ly9kdHoucm9ja3MvaWRlbnRpdHkvYXNzdW1lLzBlNGRhYzI0LWRkMjMtNDY1NS1hNDcxLTUyNjUzYTEwZDE1ZiIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2Fzc3VtZS8zZmY2MGMzZC1hOTJlLTRhNmEtYjFlYS1hMjhmMmEzNmI0MTYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hc3N1bWUvZGQzYTZkYzAtODZkZi00YTNhLWFiYzQtZTMzMGU0MWNkMjVhIiwiaHR0cHM6Ly9kdHoucm9ja3MvYmlsbGluZy9hZG1pbi8wZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hZG1pbi8wZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJodHRwczovL2R0ei5yb2Nrcy9jb250ZXh0L2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL2NvbnRleHQvYWRtaW4vZDZjYWYxN2EtZTI3Yi00NzA4LWExNzEtODY5MGQ4ZjEyYWZlIiwiaHR0cHM6Ly9kdHoucm9ja3MvY29udGFpbmVycy9hZG1pbi9kNmNhZjE3YS1lMjdiLTQ3MDgtYTE3MS04NjkwZDhmMTJhZmUiXSwiZXhwIjoxNjgwODUzMzY1LCJpYXQiOjE2ODA3NjY5NjV9";
    let decoded = Base64UrlSafe::decode_to_vec(encoded, None).unwrap();
    let json_str = String::from_utf8_lossy(&decoded);
    let json: Value = serde_json::de::from_str(&json_str).unwrap();
    let scope = json.get("scope").unwrap().as_str().unwrap();
    assert_eq!(scope, "3cd84429-64a4-4226-b868-c83feeff0f46")
}

#[test]
fn claims_decode_subject() {
    use ct_codecs::{Base64UrlSafe, Decoder};
    let encoded = "eyJpc3MiOiJkdHoucm9ja3MiLCJzdWIiOiIwZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJhdWQiOiJkdHoucm9ja3MiLCJzY29wZSI6IjNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsInJvbGVzIjpbImh0dHBzOi8vZHR6LnJvY2tzL2Zsb3dzL2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL29ic2VydmFiaWxpdHkvYWRtaW4vM2NkODQ0MjktNjRhNC00MjI2LWI4NjgtYzgzZmVlZmYwZjQ2IiwiaHR0cHM6Ly9kdHoucm9ja3Mvb2JzZXJ2YWJpbGl0eS9hZG1pbi9kM2UxNDQyMi03YWJjLTQzMGQtYmU0OS1kNDNlY2RiMjVhYTYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hZG1pbi83OWU2ZmJmZS1kYTFmLTRjMzgtOGE5Ny00M2U4NDlmYzk4ZWEiLCJodHRwczovL2R0ei5yb2Nrcy9vYnNlcnZhYmlsaXR5L2FkbWluLzc5ZTZmYmZlLWRhMWYtNGMzOC04YTk3LTQzZTg0OWZjOThlYSIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluL2Q2Y2FmMTdhLWUyN2ItNDcwOC1hMTcxLTg2OTBkOGYxMmFmZSIsImh0dHBzOi8vZHR6LnJvY2tzL2NvbnRhaW5lcnMvYWRtaW4vM2NkODQ0MjktNjRhNC00MjI2LWI4NjgtYzgzZmVlZmYwZjQ2IiwiaHR0cHM6Ly9kdHoucm9ja3MvaWRlbnRpdHkvYXNzdW1lLzBlNGRhYzI0LWRkMjMtNDY1NS1hNDcxLTUyNjUzYTEwZDE1ZiIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2Fzc3VtZS8zZmY2MGMzZC1hOTJlLTRhNmEtYjFlYS1hMjhmMmEzNmI0MTYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hc3N1bWUvZGQzYTZkYzAtODZkZi00YTNhLWFiYzQtZTMzMGU0MWNkMjVhIiwiaHR0cHM6Ly9kdHoucm9ja3MvYmlsbGluZy9hZG1pbi8wZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hZG1pbi8wZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJodHRwczovL2R0ei5yb2Nrcy9jb250ZXh0L2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL2NvbnRleHQvYWRtaW4vZDZjYWYxN2EtZTI3Yi00NzA4LWExNzEtODY5MGQ4ZjEyYWZlIiwiaHR0cHM6Ly9kdHoucm9ja3MvY29udGFpbmVycy9hZG1pbi9kNmNhZjE3YS1lMjdiLTQ3MDgtYTE3MS04NjkwZDhmMTJhZmUiXSwiZXhwIjoxNjgwODUzMzY1LCJpYXQiOjE2ODA3NjY5NjV9";
    let decoded = Base64UrlSafe::decode_to_vec(encoded, None).unwrap();
    let json_str = String::from_utf8_lossy(&decoded);
    let json: Value = serde_json::de::from_str(&json_str).unwrap();
    let subject = json.get("sub").unwrap().as_str().unwrap();
    assert_eq!(subject, "0e4dac24-dd23-4655-a471-52653a10d15f")
}

#[test]
fn verify_broken_token() {
    let public_key = RS256PublicKey::from_pem(PUBLIC_KEY).unwrap();
    let token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImR0ejEifQ.eyJpc3MiOiJkdHoucm9ja3MiLCJzdWIiOiIwZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJhdWQiOiJkdHoucm9ja3MiLCJzY29wZSI6IjNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsInJvbGVzIjpbImh0dHBzOi8vZHR6LnJvY2tzL2Zsb3dzL2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL29ic2VydmFiaWxpdHkvYWRtaW4vM2NkODQ0MjktNjRhNC00MjI2LWI4NjgtYzgzZmVlZmYwZjQ2IiwiaHR0cHM6Ly9kdHoucm9ja3Mvb2JzZXJ2YWJpbGl0eS9hZG1pbi9kM2UxNDQyMi03YWJjLTQzMGQtYmU0OS1kNDNlY2RiMjVhYTYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hZG1pbi83OWU2ZmJmZS1kYTFmLTRjMzgtOGE5Ny00M2U4NDlmYzk4ZWEiLCJodHRwczovL2R0ei5yb2Nrcy9vYnNlcnZhYmlsaXR5L2FkbWluLzc5ZTZmYmZlLWRhMWYtNGMzOC04YTk3LTQzZTg0OWZjOThlYSIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluL2Q2Y2FmMTdhLWUyN2ItNDcwOC1hMTcxLTg2OTBkOGYxMmFmZSIsImh0dHBzOi8vZHR6LnJvY2tzL2NvbnRhaW5lcnMvYWRtaW4vM2NkODQ0MjktNjRhNC00MjI2LWI4NjgtYzgzZmVlZmYwZjQ2IiwiaHR0cHM6Ly9kdHoucm9ja3MvaWRlbnRpdHkvYXNzdW1lLzBlNGRhYzI0LWRkMjMtNDY1NS1hNDcxLTUyNjUzYTEwZDE1ZiIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2Fzc3VtZS8zZmY2MGMzZC1hOTJlLTRhNmEtYjFlYS1hMjhmMmEzNmI0MTYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hc3N1bWUvZGQzYTZkYzAtODZkZi00YTNhLWFiYzQtZTMzMGU0MWNkMjVhIiwiaHR0cHM6Ly9kdHoucm9ja3MvYmlsbGluZy9hZG1pbi8wZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hZG1pbi8wZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJodHRwczovL2R0ei5yb2Nrcy9jb250ZXh0L2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL2NvbnRleHQvYWRtaW4vZDZjYWYxN2EtZTI3Yi00NzA4LWExNzEtODY5MGQ4ZjEyYWZlIiwiaHR0cHM6Ly9kdHoucm9ja3MvY29udGFpbmVycy9hZG1pbi9kNmNhZjE3YS1lMjdiLTQ3MDgtYTE3MS04NjkwZDhmMTJhZmUiXSwiZXhwIjoxNjgwODUzMzY1LCJpYXQiOjE2ODA3NjY5NjV9.ACZ1x_L32jZj7iWZjarhuLssKkfOzkZbcToSVe9FEL8Y7iBo1Hlo8XIg26mq7dqDJCJhtS0KQAWDZq4rXq_nu0tiUWmL6ZlX3A0HlWjxBH1kbcwc4sMVbj3-k0Z7n3aTK_LH0hcoImYt7nBcV0naK4ZrLrPvSTWuOEw7TNCeh1kJitheXUvWxvBLG-1iK9QEDIVuRZk0KvhBajA2LM5DxnFw1nBVV6Ih8Maw_gU74s24VdhtsLievom4u_PR-CeeMR11Y1Xi9n7TrcAKH3RaeNIWDEuXcR-RFg99kUArcvVS12Bbkc7gf0MPo-APB_csO1ppbSJ9yXUHghsIRYN3xg";
    let claims = public_key.verify_token::<NoCustomClaims>(&token, None);
    assert!(claims.is_err())
}

#[test]
fn test_b64() {
    let b64 = r#"eyJpc3MiOiJkdHoucm9ja3MiLCJzdWIiOiI3MDA1ZDhiYi1hYzVlLTRiYjctYTRmNS04MzE0ODg4ZjRjYjQiLCJhdWQiOiJkdHoucm9ja3MiLCJzY29wZSI6IjA2ZDljODVkLWNiNTItNDVmYS04ZjFiLTVjYWQ0YmYwN2I5YyIsInJvbGVzIjpbImh0dHBzOi8vZHR6LnJvY2tzL2Zsb3dzL2FkbWluLzA2ZDljODVkLWNiNTItNDVmYS04ZjFiLTVjYWQ0YmYwN2I5YyIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluLzcwMDVkOGJiLWFjNWUtNGJiNy1hNGY1LTgzMTQ4ODhmNGNiNCJdLCJleHAiOjE2ODU2MTAwNjIsImlhdCI6MTY4NTUyMzY2Mn0"#;
    use base64::{engine::general_purpose, Engine as _};

    let decoded = general_purpose::STANDARD_NO_PAD.decode(b64).unwrap();
    let str = String::from_utf8_lossy(&decoded);
    println!("{str}");
}

#[test]
fn test_b64_2() {
    let b64 = r#"eyJpc3MiOiJkdHoucm9ja3MiLCJzdWIiOiIwZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJhdWQiOiJkdHoucm9ja3MiLCJzY29wZSI6IjNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsInJvbGVzIjpbImh0dHBzOi8vZHR6LnJvY2tzL2Zsb3dzL2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL29ic2VydmFiaWxpdHkvYWRtaW4vM2NkODQ0MjktNjRhNC00MjI2LWI4NjgtYzgzZmVlZmYwZjQ2IiwiaHR0cHM6Ly9kdHoucm9ja3Mvb2JzZXJ2YWJpbGl0eS9hZG1pbi9kM2UxNDQyMi03YWJjLTQzMGQtYmU0OS1kNDNlY2RiMjVhYTYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hZG1pbi83OWU2ZmJmZS1kYTFmLTRjMzgtOGE5Ny00M2U4NDlmYzk4ZWEiLCJodHRwczovL2R0ei5yb2Nrcy9vYnNlcnZhYmlsaXR5L2FkbWluLzc5ZTZmYmZlLWRhMWYtNGMzOC04YTk3LTQzZTg0OWZjOThlYSIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluL2Q2Y2FmMTdhLWUyN2ItNDcwOC1hMTcxLTg2OTBkOGYxMmFmZSIsImh0dHBzOi8vZHR6LnJvY2tzL2NvbnRhaW5lcnMvYWRtaW4vM2NkODQ0MjktNjRhNC00MjI2LWI4NjgtYzgzZmVlZmYwZjQ2IiwiaHR0cHM6Ly9kdHoucm9ja3MvaWRlbnRpdHkvYXNzdW1lLzBlNGRhYzI0LWRkMjMtNDY1NS1hNDcxLTUyNjUzYTEwZDE1ZiIsImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2Fzc3VtZS8zZmY2MGMzZC1hOTJlLTRhNmEtYjFlYS1hMjhmMmEzNmI0MTYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hc3N1bWUvZGQzYTZkYzAtODZkZi00YTNhLWFiYzQtZTMzMGU0MWNkMjVhIiwiaHR0cHM6Ly9kdHoucm9ja3MvYmlsbGluZy9hZG1pbi8wZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJodHRwczovL2R0ei5yb2Nrcy9pZGVudGl0eS9hZG1pbi8wZTRkYWMyNC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJodHRwczovL2R0ei5yb2Nrcy9jb250ZXh0L2FkbWluLzNjZDg0NDI5LTY0YTQtNDIyNi1iODY4LWM4M2ZlZWZmMGY0NiIsImh0dHBzOi8vZHR6LnJvY2tzL2NvbnRleHQvYWRtaW4vZDZjYWYxN2EtZTI3Yi00NzA4LWExNzEtODY5MGQ4ZjEyYWZlIiwiaHR0cHM6Ly9kdHoucm9ja3MvY29udGFpbmVycy9hZG1pbi9kNmNhZjE3YS1lMjdiLTQ3MDgtYTE3MS04NjkwZDhmMTJhZmUiLCJodHRwczovL2R0ei5yb2Nrcy9vYmplY3RzdG9yZS9hZG1pbi8zY2Q4NDQyOS02NGE0LTQyMjYtYjg2OC1jODNmZWVmZjBmNDYiXSwiZXhwIjoxNjg1NTY3MDE0LCJpYXQiOjE2ODU0ODA2MTR9"#;
    use base64::{engine::general_purpose, Engine as _};

    let decoded = general_purpose::STANDARD_NO_PAD.decode(b64).unwrap();
    let str = String::from_utf8_lossy(&decoded);
    println!("{str}");
}

#[test]
fn test_b64_basic_auth() {
    let b64 = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==";
    use base64::{engine::general_purpose, Engine as _};

    let decoded = general_purpose::STANDARD.decode(b64).unwrap();
    let str = String::from_utf8_lossy(&decoded);
    let parts: Vec<&str> = str.split(':').collect();
    println!("{parts:?}");
    assert_eq!(parts[0], "Aladdin");
    assert_eq!(parts[1], "open sesame");
}

#[test]
fn multiple_cookies() {
    let cookie_str = "ph_phc_Tbfg4EiRsr5iefFoth2Y1Hi3sttTeLQ5RV5TLg4hL1W_posthog=%7B%22distinct_id%22%3A%2218eeb867e3f2227-01a05f116afd35-1c525637-384000-18eeb867e4048f2%22%2C%22%24device_id%22%3A%2218eeb867e3f2227-01a05f116afd35-1c525637-384000-18eeb867e4048f2%22%2C%22%24user_state%22%3A%22anonymous%22%2C%22%24sesid%22%3A%5B1713349513245%2C%2218eeb867eb51c05-014402dc1a36-1c525637-384000-18eeb867eb65080%22%2C1713348443829%5D%2C%22%24session_recording_enabled_server_side%22%3Afalse%2C%22%24autocapture_disabled_server_side%22%3Afalse%2C%22%24active_feature_flags%22%3A%5B%5D%2C%22%24enabled_feature_flags%22%3A%7B%7D%2C%22%24feature_flag_payloads%22%3A%7B%7D%7D; dtz-auth=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImR0ejEifQ.eyJpc3MiOiJkdHoucm9ja3MiLCJzdWIiOiIwMDAwMDAwMC1kZDIzLTQ2NTUtYTQ3MS01MjY1M2ExMGQxNWYiLCJhdWQiOiJkdHoucm9ja3MiLCJzY29wZSI6IjAwMDAwMDAwLTJlMGQtNDNhMS1hOTJjLTU0NTQ2YWQ1YjFmYiIsInJvbGVzIjpbImh0dHBzOi8vZHR6LnJvY2tzL2lkZW50aXR5L2FkbWluLzAwMDAwMDAwLWUyN2ItNDcwOC1hMTcxLTg2OTBkOGYxMmFmZSJdLCJjb250ZXh0cyI6WyIwMDAwMDAwMC03N2I2LTQ2YmYtODU4Yi01OGRiMjI4NjdlYWQiXSwiZXhwIjoxNzEzNDMxMjAxLCJpYXQiOjE3MTMzNDQ4MDF9.PYbsoDYdMg-kv0b5iqMV1QqTT2IG38HWc_YarzlXR5kXgWCaH6wm24xDz8G6-QQENvaZ0uLNOz6YZh6mX7a5bi4-_m9CXysmJJ4i2wP9kfjXdprSmqefYpVkAOljOoCHSIGhsuyOd5PZH0YBM5q-dMgBbEp00oLz9YDL_yQ9zwKUuePYu6Z53FgIA26WwxzSTMook7XkATtc7Cl7ktSHP_ieUWWT_RyU3eOIPmCrpTv4jFyg0sh-ylG3qeKl2utEC4ZzjzJ8av_e29Q74n_H29LOnWVAThhZ9qXkGAxP0CCQuJm0Ig0RuxKQ4qfLE0PYIZ2XIKNIpIurWOEGl1Zv2w";
    let cookie = HeaderValue::from_static(cookie_str);
    let result = crate::verify_token_from_cookie(cookie);
    println!("{result:?}");
    assert!(result.is_err());
    match result {
        Err(msg) => {
            if msg == "invalid token" {
                // signature is wrong, but jwt could be read
                assert!(true)
            } else {
                assert!(false)
            }
        }
        _ => assert!(false),
    }
}
