#![deny(missing_docs)]
#![feature(adt_const_params)]

//! crate to provide trait for easier implementation of user profiles within [DownToZero.cloud](https://downtozero.cloud)
use serde::{Serialize,Deserialize};
use axum::{
  async_trait,
  extract::{FromRequest, RequestParts},
  http::header::HeaderValue,
  http::{StatusCode},
};
use uuid::Uuid;
use jwt::PKeyWithDigest;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use jwt::algorithm::VerifyingAlgorithm;
use jwt::claims::Claims;
use jwt::FromBase64;
use cookie::Cookie;

/// public key used for JWT signature verification
const PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0gVBfnAa7748XyjOYXQ5
Yf39yKJ/t3b2wF5F1yPUuyLanwZYTGBV804Vs0YWiiKJ1H/csI3jWX5CWkV5TzMx
CIP4kCugsFH6wP8rCt8Vei+rdJFB/LrlYz8Ks8Td60c5t/Hq9yQEz6kIpa5TmZw2
DSDPvOKXW2SJRPCqj3JEk6fHsJ6nZ2BIoFvs6NMRNqgSEHr1x7lUUt9teWM2wOtF
ze24D+luvXWhRUjMMvMKkPuxdS6mPbXqoyde3U9tcsC+t2tThqVaREPkj6ew1IcU
RnoXLi+43p4j4cQqxRjG3DzzjqAlivFjlGR/vqfLvUrGP9opjI+zs3l4G8IYWsqM
KQIDAQAB
-----END PUBLIC KEY-----"#;

/// User profile of DownToZero.cloud
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DtzProfile {
  /// Identifier of the user
  pub identity_id: Uuid,
  /// current context of the authnetication
  pub context_id: Uuid,
  /// available roles granted to the user
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub roles: Vec<String>,
}

/// struct to hold an authorized user profile
pub struct DtzRequiredRole<const N: &'static str>(pub DtzProfile);

#[async_trait]
impl<B, const N: &'static str> FromRequest<B> for DtzRequiredRole<N>
where
  B: Send,
{
  type Rejection = (StatusCode, &'static str);

  async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
    let cookie: Option<&HeaderValue> = req.headers().and_then(|headers| headers.get("cookie"));
    let authorization: Option<&HeaderValue> = req.headers().and_then(|headers| headers.get("authorization"));
    let profile: DtzProfile;
    if let Some(cookie) = cookie {
      profile = verify_token_from_cookie(cookie.clone()).unwrap();
    }else if let Some(authorization) = authorization {
      profile = verify_token_from_bearer(authorization.clone()).unwrap();
    }else {
      return Err((StatusCode::UNAUTHORIZED, "no authorization header"));
    }

    let scope = replace_placeholder(N, &profile);
    if !profile.roles.contains(&scope) {
      return Err((StatusCode::FORBIDDEN, "no permission"));
    }
    Ok(DtzRequiredRole(profile))
  }
}

/// struct to hold an authenticated user profile
pub struct DtzRequiredUser(pub DtzProfile);

#[async_trait]
impl<B> FromRequest<B> for DtzRequiredUser
where
    B: Send,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let identity = req.headers().and_then(|headers| headers.get("dtz-identity"));
        let context = req.headers().and_then(|headers| headers.get("dtz-context"));
        let roles = req.headers().and_then(|headers| headers.get("dtz-roles"));

        let mut profile = DtzProfile::default();
        if let Some(identity) = identity {
          profile.identity_id = Uuid::parse_str(identity.to_str().unwrap()).unwrap();
        }
        if let Some(context) = context {
          let context_str = context.to_str().unwrap().to_string();
          if context_str.len() != 36 {
            eprintln!("invalid context id: {}", context_str);
            return Err((StatusCode::UNAUTHORIZED, "invalid context id"));
          }else{
            profile.context_id = Uuid::parse_str(&context_str).unwrap();
          }
        }
        if let Some(roles) = roles {
          let arr: Vec<&str> = roles.to_str().unwrap().split(',').collect();
          let mut roles: Vec<String> = Vec::new();
          for role in arr {
            roles.push(role.to_string());
          }
          profile.roles = roles;
        }
        Ok(DtzRequiredUser(profile))
    }
}

/// struct to hold a user profile, if a user is authenticated
pub struct DtzOptionalUser(pub Option<DtzProfile>);

#[async_trait]
impl<B> FromRequest<B> for DtzOptionalUser
where
    B: Send,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let identity = req.headers().and_then(|headers| headers.get("dtz-identity"));
        let context = req.headers().and_then(|headers| headers.get("dtz-context"));
        let roles = req.headers().and_then(|headers| headers.get("dtz-roles"));

        let mut profile = DtzProfile::default();
        if let Some(identity) = identity {
          profile.identity_id = Uuid::parse_str(identity.to_str().unwrap()).unwrap();
        }else{
          return Ok(DtzOptionalUser(None));
        }
        if let Some(context) = context {
          let context_str = context.to_str().unwrap().to_string();
          if context_str.len() != 36 {
            eprintln!("invalid context id: {}", context_str);
            return Err((StatusCode::UNAUTHORIZED, "invalid context id"));
          }else{
            profile.context_id = Uuid::parse_str(&context_str).unwrap();
          }
        }
        if let Some(roles) = roles {
          let arr: Vec<&str> = roles.to_str().unwrap().split(',').collect();
          let mut roles: Vec<String> = Vec::new();
          for role in arr {
            roles.push(role.to_string());
          }
          profile.roles = roles;
        }
        Ok(DtzOptionalUser(Some(profile)))
    }
}

fn verify_token_from_cookie(cookie: HeaderValue) -> Result<DtzProfile,String> {
  let cookie_str = cookie.to_str().unwrap();
  let c = Cookie::parse(cookie_str).unwrap();
  let jwt = c.value().to_string();
  verify_token(jwt)
}

fn verify_token_from_bearer(bearer: HeaderValue) -> Result<DtzProfile,String> {
  let bearer_str = bearer.to_str().unwrap();
  let jwt = bearer_str.replace("Bearer ","");
  verify_token(jwt)
}

fn verify_token(token: String) -> Result<DtzProfile,String> {

  if token.as_str().contains('.') {
    let jwt_parts: Vec<&str> = token.split('.').collect();
    let jwt_alg = jwt_parts.get(0).unwrap();
    let jwt_payload = jwt_parts.get(1).unwrap();
    let jwt_sig = jwt_parts.get(2).unwrap();
    let algorithm = PKeyWithDigest {
      digest: MessageDigest::sha256(),
      key: PKey::public_key_from_pem(PUBLIC_KEY.as_bytes()).unwrap(),
    };
    // trace!("payload: {}",jwt_payload);
    let _verification_result = algorithm.verify(jwt_alg, jwt_payload, jwt_sig).unwrap();
    let claims = Claims::from_base64(jwt_payload).unwrap();
    let roles_claim = claims.private.get("roles").unwrap();
    let mut roles: Vec<String> = Vec::new();
    let arr = roles_claim.as_array().unwrap();
    for role in arr {
      roles.push(role.as_str().unwrap().to_string());
    }
    let scope_str = claims.private.get("scope").unwrap().as_str().unwrap();
    let result = DtzProfile{
      identity_id: Uuid::parse_str(&claims.registered.subject.unwrap()).unwrap(),
      context_id: Uuid::parse_str(scope_str).unwrap(),
      roles,
    };
    Ok(result)
  }else{
    //deny
    Err("not authorized".to_string())
  }
}

fn replace_placeholder(template: &str, profile: &DtzProfile) -> String {
  let mut result = template.to_string();
  result = result.replace("{identity_id}", &profile.identity_id.to_string());
  result = result.replace("{context_id}", &profile.context_id.to_string());
  result = result.replace("{roles}", &profile.roles.join(","));
  result
}

#[cfg(test)]
mod tests {
  use uuid::Uuid;
  use super::*;
  #[test]
  fn test_replacement_identity() {
    let identity = DtzProfile{
      identity_id: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
      context_id: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
      roles: vec!["admin".to_string()],
    };
    let result = super::replace_placeholder("https://dtz.rocks/context/admin/{identity_id}", &identity);
    assert_eq!(result, "https://dtz.rocks/context/admin/00000000-0000-0000-0000-000000000000");
  }
  #[test]
  fn test_replacement_context() {
    let identity = DtzProfile{
      identity_id: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
      context_id: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
      roles: vec!["admin".to_string()],
    };
    let result = super::replace_placeholder("https://dtz.rocks/context/admin/{context_id}", &identity);
    assert_eq!(result, "https://dtz.rocks/context/admin/00000000-0000-0000-0000-000000000000");
  }
  #[test]
  fn test_replacement_nothing() {
    let identity = DtzProfile{
      identity_id: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
      context_id: Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap(),
      roles: vec!["admin".to_string()],
    };
    let result = super::replace_placeholder("https://dtz.rocks/context/admin", &identity);
    assert_eq!(result, "https://dtz.rocks/context/admin");
  }
}
