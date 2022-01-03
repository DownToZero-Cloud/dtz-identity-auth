#![deny(missing_docs)]
//! crate to provide trait for easier implementation of user profiles within [DownToZero.cloud](https://downtozero.cloud)
use serde::{Serialize,Deserialize};
use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    http::{StatusCode},
};
use uuid::Uuid;

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

/// struct to hold an authenticated user profile
pub struct DtzRequiredUser(pub DtzProfile);
/// struct to hold a user profile, if a user is authenticated
pub struct DtzOptionalUser(pub Option<DtzProfile>);

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
          profile.identity_id = Uuid::parse_str(&identity.to_str().unwrap().to_string()).unwrap();
        }
        if let Some(context) = context {
          let context_str = context.to_str().unwrap().to_string();
          if context_str.len() != 36 {
            return Err((StatusCode::UNAUTHORIZED, format!("invalid context id: {}", context_str)));
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
          profile.identity_id = Uuid::parse_str(&identity.to_str().unwrap().to_string()).unwrap();
        }else{
          return Ok(DtzOptionalUser(None));
        }
        if let Some(context) = context {
          let context_str = context.to_str().unwrap().to_string();
          if context_str.len() != 36 {
            return Err((StatusCode::UNAUTHORIZED, format!("invalid context id: {}", context_str)));
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
