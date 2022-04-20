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
use hyper::{Body, Request,Client,Method};
use hyper::body;
use lru_time_cache::LruCache;
use std::sync::Mutex;
use once_cell::sync::Lazy;

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
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
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
    let result = get_profile_from_request(req).await;
    match result {
        Ok(profile) => {
            let scope = replace_placeholder(N, &profile);
            if !profile.roles.contains(&scope) {
                return Err((StatusCode::FORBIDDEN, "no permission"));
            }
            Ok(DtzRequiredRole(profile))
        },
        Err(e) => Err((StatusCode::UNAUTHORIZED, &e)),
    } 
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
        let result = get_profile_from_request(req).await;
        match result {
            Ok(profile) => Ok(DtzRequiredUser(profile)),
            Err(e) => Err((StatusCode::UNAUTHORIZED, e)),
        }
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
        let result = get_profile_from_request(req).await;
        match result {
            Ok(profile) => Ok(DtzOptionalUser(Some(profile))),
            Err(_e) => Ok(DtzOptionalUser(None)),
        }
    }
}

async fn get_profile_from_request<B>(req: &mut RequestParts<B>) -> Result<DtzProfile,&'static str> {
  let headers = req.headers().clone();
  let cookie: Option<&HeaderValue> = headers.get("cookie");
  let authorization: Option<&HeaderValue> = headers.get("authorization");
  let header_api_key: Option<&HeaderValue> = headers.get("x-api-key");
  let header_context_id: Option<&HeaderValue> = headers.get("x-dtz-context");
  let profile: DtzProfile;
  if let Some(cookie) = cookie {
    match verify_token_from_cookie(cookie.clone()) {
      Ok(p) => {
        profile = p;
      },
      Err(_) => {
        return Err("no valid token found in cookie");
      }
    }
  }else if let Some(authorization) = authorization {
    match verify_token_from_bearer(authorization.clone()) {
      Ok(p) => {
        profile = p;
      },
      Err(_) => {
        return Err("not authorized");
      }
    }
  }else if let Some(header_api_key) = header_api_key {
    if header_context_id.is_some() {
      profile = verifiy_api_key(header_api_key.to_str().unwrap(), Some(header_context_id.unwrap().to_str().unwrap())).await.unwrap();
    }else{
      profile = verifiy_api_key(header_api_key.to_str().unwrap(), None).await.unwrap();
    }
  }else {
    //look for GET params
    let query = req.uri().query().unwrap_or_default();
    let value: GetAuthParams = serde_urlencoded::from_str(query).unwrap();
    if value.api_key.is_some() {
      if value.context_id.is_some() {
        profile = verifiy_api_key(&value.api_key.unwrap(), Some(&value.context_id.unwrap())).await.unwrap();
      }else{
        profile = verifiy_api_key(&value.api_key.unwrap(), None).await.unwrap();
      }
    }else{
      return Err("no authorization header");
    }
  }
  Ok(profile)
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
    match algorithm.verify(jwt_alg, jwt_payload, jwt_sig) {
      Ok(_) => {
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
      },
      Err(_) => {
        return Err("invalid token".to_string());
      }
    }
  }else{
    //deny
    Err("not authorized".to_string())
  }
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenResponse {
  access_token: String,
  scope: Option<String>,
  token_type: String,
  expires_in: u32,
}


#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct GetAuthParams {
  api_key: Option<String>,
  context_id: Option<String>,
}

static KNOWN_IDENTITIES: Lazy<Mutex<LruCache::<String, DtzProfile>>> = Lazy::new(|| {
    let time_to_live = std::time::Duration::from_secs(3600);
    let m = LruCache::<String, DtzProfile>::with_expiry_duration_and_capacity(time_to_live,100);
    Mutex::new(m)
});

async fn verifiy_api_key(api_key: &str, context_id: Option<&str>) -> Result<DtzProfile,String> {
  let req_data = if context_id.is_some() {
    format!("{{\"apiKey\":\"{}\",\"contextId\":\"{}\"}}",api_key,context_id.unwrap())
  } else {
    format!("{{\"apiKey\":\"{}\"}}",api_key)
  };
  {
    let mut x = KNOWN_IDENTITIES.lock().unwrap();
    if x.contains_key(&req_data){
      let profile = x.get(&req_data).unwrap().clone();
      return Ok(profile);
    }
  }
  //get hostname env var
  let hostname = std::env::var("HOSTNAME").unwrap_or("localhost".to_string());
  let req = Request::builder()
      .method(Method::POST)
      .uri("https://identity.dtz.rocks/api/2021-02-21/auth/apikey")
      .header("content-type", "application/json")
      .header("X-DTZ-SOURCE", hostname)
      .body(Body::from(req_data.clone())).unwrap();
  let https = hyper_rustls::HttpsConnectorBuilder::new()
      .with_native_roots()
      .https_only()
      .enable_http1()
      .build();
  let http_client = Client::builder().build(https);
  let resp = http_client.request(req).await.unwrap();
  if resp.status().is_success() {
    let bytes = body::to_bytes(resp.into_body()).await.unwrap();
    let resp_str = String::from_utf8(bytes.to_vec()).expect("response was not valid utf-8");
    let token_response: TokenResponse = serde_json::from_str(&resp_str).unwrap();
    let jwt = token_response.access_token;
    let result = verify_token(jwt);
    //add to cache
    {
      if result.is_ok() {
        let mut x = KNOWN_IDENTITIES.lock().unwrap();
        x.insert(req_data,result.clone().unwrap());
      }
    }
    result
  }else{
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

/// verifies the role on a given profile
pub fn verify_role(profile: &DtzProfile, role: &str) -> bool {
  profile.roles.contains(&role.to_string())
}

/// verifies the role on a given profile within the current context
pub fn verfify_context_role(profile: &DtzProfile, role: &str) -> bool {
  let replaced_role = replace_placeholder(role, profile);
  profile.roles.contains(&replaced_role.to_string())
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
