use serde::{Serialize,Deserialize};
use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    http::{StatusCode},
};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct DtzProfile{
  pub identity_id: Uuid,
  pub context_id: Uuid,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  pub roles: Vec<String>,
}
pub struct DtzUser(DtzProfile);

#[async_trait]
impl<B> FromRequest<B> for DtzUser
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
          profile.context_id = Uuid::parse_str(&context.to_str().unwrap().to_string()).unwrap();
        }
        if let Some(roles) = roles {
          let arr: Vec<&str> = roles.to_str().unwrap().split(',').collect();
          let mut roles: Vec<String> = Vec::new();
          for role in arr {
            roles.push(role.to_string());
          }
          profile.roles = roles;
        }
        Ok(DtzUser(profile))
    }
}