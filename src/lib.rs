#![deny(missing_docs)]

//! crate to provide trait for easier implementation of user profiles within [DownToZero.cloud](https://downtozero.cloud)
use axum::{
    async_trait, extract::FromRequestParts, http::header::HeaderValue, http::request::Parts,
    http::StatusCode,
};
use base64::{engine::general_purpose, Engine as _};
use cookie::Cookie;
use dtz_identifier::{ApiKeyId, ContextId, IdentityId};
use http_body_util::BodyExt;
use hyper::{Method, Request};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use jwt_simple::prelude::{NoCustomClaims, RS256PublicKey, RSAPublicKeyLike};
use lru_time_cache::LruCache;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{sync::Mutex, time::Duration};
use uuid::Uuid;

#[cfg(test)]
mod test;

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
    pub identity_id: IdentityId,
    /// current context of the authnetication
    pub context_id: ContextId,
    /// available roles granted to the user
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    /// raw token of the request, if api key was used, a new token is generated
    pub token: String,
}

/// struct to hold an authenticated user profile
pub struct DtzRequiredUser(pub DtzProfile);

impl DtzProfile {
    /// checks the profile for the required scope
    #[allow(dead_code)]
    pub fn require(&self, required_role: &str) -> bool {
        let scope = replace_placeholder(required_role, self);
        self.roles.contains(&scope)
    }
}

#[async_trait]
impl<B> FromRequestParts<B> for DtzRequiredUser
where
    B: Send + std::marker::Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(req: &mut Parts, _state: &B) -> Result<Self, Self::Rejection> {
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
impl<B> FromRequestParts<B> for DtzOptionalUser
where
    B: Send + std::marker::Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(req: &mut Parts, _state: &B) -> Result<Self, Self::Rejection> {
        let result = get_profile_from_request(req).await;
        match result {
            Ok(profile) => Ok(DtzOptionalUser(Some(profile))),
            Err(_e) => Ok(DtzOptionalUser(None)),
        }
    }
}

async fn get_profile_from_request(req: &mut Parts) -> Result<DtzProfile, String> {
    let headers = req.headers.clone();
    let cookie: Option<&HeaderValue> = headers.get("cookie");
    let authorization: Option<&HeaderValue> = headers.get("authorization");
    let header_api_key: Option<&HeaderValue> = headers.get("x-api-key");
    let header_context_id: Option<&HeaderValue> = headers.get("x-dtz-context");
    let profile: DtzProfile;
    if let Some(cookie) = cookie {
        match verify_token_from_cookie(cookie.clone()) {
            Ok(p) => {
                profile = p;
            }
            Err(_) => {
                return Err("no valid token found in cookie".to_string());
            }
        }
    } else if let Some(authorization) = authorization {
        let auth_str = authorization.to_str().unwrap();
        if auth_str.starts_with("Basic ") {
            match verify_basic_auth(authorization).await {
                Ok(p) => {
                    profile = p;
                }
                Err(_) => {
                    return Err("not authorized".to_string());
                }
            }
        } else if auth_str.starts_with("Bearer ") {
            match verify_token_from_bearer(authorization.clone()) {
                Ok(p) => {
                    profile = p;
                }
                Err(_) => {
                    return Err("not authorized".to_string());
                }
            }
        } else {
            return Err("not authorized".to_string());
        }
    } else if let Some(header_api_key) = header_api_key {
        if let Some(context_id) = header_context_id {
            if context_id.is_empty() {
                let result = ApiKeyId::try_from(header_api_key.to_str().unwrap());
                return match result {
                    Ok(key) => verifiy_api_key(&key, None).await,
                    Err(err) => Err(err),
                };
            } else {
                let api_key = ApiKeyId::try_from(header_api_key.to_str().unwrap());
                let context_id = ContextId::try_from(context_id.to_str().unwrap());
                match (api_key, context_id) {
                    (Ok(api_key), Ok(context_id)) => {
                        return verifiy_api_key(&api_key, Some(&context_id)).await;
                    }
                    _ => {
                        //fail
                        return Err("not authorized".to_string());
                    }
                }
            }
        } else {
            let result = ApiKeyId::try_from(header_api_key.to_str().unwrap());
            return match result {
                Ok(key) => verifiy_api_key(&key, None).await,
                Err(err) => Err(err),
            };
        }
    } else {
        //look for GET params
        let query = req.uri.query().unwrap_or_default();
        let value: GetAuthParams = serde_urlencoded::from_str(query).unwrap();
        return verify_query_params(value).await;
    }
    Ok(profile)
}

async fn verify_query_params(value: GetAuthParams) -> Result<DtzProfile, String> {
    if value.api_key.is_some() {
        if value.context_id.is_none() {
            let result = ApiKeyId::try_from(value.api_key.unwrap_or_default().as_str());
            match result {
                Ok(key) => verifiy_api_key(&key, None).await,
                Err(err) => Err(err),
            }
        } else {
            let api_key = ApiKeyId::try_from(value.api_key.unwrap_or_default().as_str());
            let context_id = ContextId::try_from(value.context_id.unwrap_or_default().as_str());
            match (api_key, context_id) {
                (Ok(api_key), Ok(context_id)) => verifiy_api_key(&api_key, Some(&context_id)).await,
                _ => {
                    //fail
                    Err("not authorized".to_string())
                }
            }
        }
    } else {
        Err("no authorization header".to_string())
    }
}

fn verify_token_from_cookie(cookie: HeaderValue) -> Result<DtzProfile, String> {
    let cookie_str = cookie.to_str().unwrap();
    let mut final_cookie = None;
    for cookie in Cookie::split_parse(cookie_str) {
        let cookie = cookie.unwrap();
        if cookie.name() == "dtz-auth" {
            let c = cookie.value().to_string();
            final_cookie = Some(c);
        }
    }
    if let Some(token) = final_cookie {
        crate::verify_token(token.to_string())
    } else {
        Err("no valid token found in cookie".to_string())
    }
}

async fn verify_basic_auth(bearer: &HeaderValue) -> Result<DtzProfile, String> {
    let bearer_str = bearer.to_str().unwrap();
    let b64 = bearer_str.replace("Basic ", "");
    let decoded = general_purpose::STANDARD.decode(b64).unwrap();
    let str = String::from_utf8_lossy(&decoded);
    let parts: Vec<&str> = str.split(':').collect();
    let cred_type = parts.first().unwrap_or(&"");
    match *cred_type {
        "apikey" => {
            let password = parts.get(1).unwrap_or(&"");
            let result = ApiKeyId::try_from(*password);
            match result {
                Ok(key) => verifiy_api_key(&key, None).await,
                Err(err) => Err(err),
            }
        }
        "bearer" => {
            let token = parts.get(1).unwrap_or(&"");
            verify_token(token.to_string())
        }
        _ => Err(
            "invalid crendential type, please use the `user` to a valid value, e.g. apikey, bearer"
                .to_string(),
        ),
    }
}

/// retrieve the profile information from a bearer token
pub fn get_profile_from_bearer(bearer: impl Into<String>) -> Result<DtzProfile, String> {
    let bearer_str = bearer.into();
    verify_token(bearer_str)
}

fn verify_token_from_bearer(bearer: HeaderValue) -> Result<DtzProfile, String> {
    let bearer_str = bearer.to_str().unwrap();
    let jwt = bearer_str.replace("Bearer ", "");
    verify_token(jwt)
}

fn verify_token(token: String) -> Result<DtzProfile, String> {
    if token.as_str().contains('.') {
        let jwt_parts: Vec<&str> = token.split('.').collect();
        let _jwt_alg = jwt_parts.first().unwrap();
        let jwt_payload = jwt_parts.get(1).unwrap();
        let _jwt_sig = jwt_parts.get(2).unwrap();
        let public_key = RS256PublicKey::from_pem(PUBLIC_KEY).unwrap();
        let claims = public_key.verify_token::<NoCustomClaims>(&token, None);
        match claims {
            Ok(_) => {
                // get claims from json
                let decoded = general_purpose::STANDARD_NO_PAD
                    .decode(jwt_payload)
                    .unwrap();
                let json_str = String::from_utf8_lossy(&decoded);
                let json: Value = serde_json::de::from_str(&json_str).unwrap();
                let roles_claim = json.get("roles").unwrap();
                // let claims = Claims::from_base64(jwt_payload).unwrap();
                // let roles_claim = claims.private.get("roles").unwrap();
                let mut roles: Vec<String> = Vec::new();
                let arr = roles_claim.as_array().unwrap();
                for role in arr {
                    roles.push(role.as_str().unwrap().to_string());
                }
                let scope_str = json.get("scope").unwrap().as_str().unwrap();
                let subject_str = json.get("sub").unwrap().as_str().unwrap();
                let identity = match IdentityId::try_from(subject_str) {
                    Ok(id) => id,
                    Err(_err) => match Uuid::parse_str(subject_str) {
                        Ok(id) => IdentityId::from(id),
                        Err(_err) => {
                            return Err("invalid token".to_string());
                        }
                    },
                };
                let context = match ContextId::try_from(scope_str) {
                    Ok(id) => id,
                    Err(_err) => match Uuid::parse_str(scope_str) {
                        Ok(id) => ContextId::from(id),
                        Err(_err) => {
                            return Err("invalid token".to_string());
                        }
                    },
                };
                let result = DtzProfile {
                    identity_id: identity,
                    context_id: context,
                    roles,
                    token,
                };
                Ok(result)
            }
            Err(_) => Err("invalid token".to_string()),
        }
    } else {
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

static ONE_HOUR: Duration = Duration::from_secs(3600);
static KNOWN_IDENTITIES: Lazy<Mutex<LruCache<String, DtzProfile>>> = Lazy::new(|| {
    let m = LruCache::<String, DtzProfile>::with_expiry_duration_and_capacity(ONE_HOUR, 100);
    Mutex::new(m)
});

async fn verifiy_api_key(
    api_key: &ApiKeyId,
    context_id: Option<&ContextId>,
) -> Result<DtzProfile, String> {
    let req_data = if context_id.is_some() {
        serde_json::json!(
            {"apiKey":api_key,
             "contextId":context_id})
        .to_string()
    } else {
        serde_json::json!({"apiKey":api_key}).to_string()
    };
    {
        let mut x = KNOWN_IDENTITIES.lock().unwrap();
        if x.contains_key(&req_data) {
            let profile = x.get(&req_data).unwrap().clone();
            return Ok(profile);
        }
    }
    //get hostname env var
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_string());
    let req = Request::builder()
        .method(Method::POST)
        .uri("https://identity.dtz.rocks/api/2021-02-21/auth/apikey")
        .header("content-type", "application/json")
        .header("X-DTZ-SOURCE", hostname)
        .body(req_data.clone())
        .unwrap();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .unwrap()
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();
    let http_client = Client::builder(TokioExecutor::new()).build(https);
    let resp = http_client.request(req).await;
    match resp {
        Ok(resp) => {
            if resp.status().is_success() {
                let bytes = resp
                    .into_body()
                    .collect()
                    .await
                    .expect("reading http response")
                    .to_bytes();
                let resp_str =
                    String::from_utf8(bytes.to_vec()).expect("response was not valid utf-8");
                let token_response: TokenResponse = serde_json::from_str(&resp_str).unwrap();
                let jwt = token_response.access_token;
                let result = verify_token(jwt);
                //add to cache
                {
                    if result.is_ok() {
                        let mut x = KNOWN_IDENTITIES.lock().unwrap();
                        x.insert(req_data, result.clone().unwrap());
                    }
                }
                result
            } else {
                Err("not authorized".to_string())
            }
        }
        Err(_err) => Err("not authorized".to_string()),
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
    profile.roles.contains(&replaced_role)
}
