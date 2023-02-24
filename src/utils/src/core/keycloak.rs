use reqwest::{Body, RequestBuilder, StatusCode};
use serde_derive::Deserialize;
use serde_derive::Serialize;
use tracing::{error};
use crate::error::app_error::AppGenericError;
use crate::error::app_integration_error::AppIntegrationError;
use crate::core::cache;

use jsonwebtoken::{Validation, Algorithm, DecodingKey, decode};
use jsonwebtoken::errors::ErrorKind;
use crate::error::app_auth_error::AppAuthError;
use crate::core::dto::keycloak_token::TokenPayload;

const TOKEN_PUBLIC_KEY: &str = "token_public_key";
const BEGIN_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\n";
const END_PUBLIC_KEY: &str = "-----END PUBLIC KEY-----\n";

pub async fn get_keycloak_token_claims(token: &str) -> Result<TokenPayload, AppGenericError> {
    let public_key = get_public_key().await.unwrap();

    let decoding_key = match DecodingKey::from_rsa_pem(&public_key[..].as_bytes()) {
        Ok(data) => Ok(data),
        Err(err) => match err.kind() {
            ErrorKind::InvalidKeyFormat => {
                delete_cached_public_key().await;
                let public_key = get_public_key().await.unwrap();
                DecodingKey::from_rsa_pem(&public_key[..].as_bytes())
                    .map_err(|err| AppAuthError::auth_error(err.to_string()))
            }
            _ => Err(AppAuthError::auth_error_for_param_value(TOKEN_PUBLIC_KEY.to_owned(), err.to_string()))
        }
    }.unwrap();


    let token_payload = match decode::<TokenPayload>(
        token,
        &decoding_key,
        &Validation::new(Algorithm::RS256),
    ) {
        Ok(c) => c.claims,
        Err(err) => {
            error!("{}", &err);
            return Err(AppAuthError::auth_error(err.to_string()));
        }
    };

    Ok(token_payload)
}


async fn get_public_key() -> Result<String, AppGenericError> {
    return if let Some(data) = get_cached_public_key().await {
        Ok(data)
    } else {
        match get_keycloak_public_key().await {
            Ok(data) => {
                set_cached_public_key(&data[..]).await;
                Ok(data)
            }
            Err(err) => Err(err)
        }
    };
}

async fn get_cached_public_key() -> Option<String> {
    cache::get_key(TOKEN_PUBLIC_KEY).await
}

async fn set_cached_public_key(value: &str) {
    cache::set_key_value(TOKEN_PUBLIC_KEY, value).await;
}

async fn delete_cached_public_key() {
    cache::del_key(TOKEN_PUBLIC_KEY).await;
}

async fn get_keycloak_public_key() -> Result<String, AppGenericError> {
    let client = reqwest::Client::new();

    let keycloak_auth_realm_url = std::env::var("KEYCLOAK_AUTH_REALM")
        .unwrap_or_else(|_| panic!("KEYCLOAK_AUTH_REALM must be set!"));

    let token_settings_response = client
        .get(keycloak_auth_realm_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await
        .map_err(|err| {
            AppIntegrationError::integration_error(err.to_string())
        })
        .unwrap();

    if !token_settings_response.status().is_success() {
        error!("status {}", &token_settings_response.status());
        if token_settings_response.status().is_client_error() {
            return Err(AppIntegrationError::integration_error("client error".to_string()));
        } else {
            return Err(AppIntegrationError::integration_error("server error".to_string()));
        }
    }

    let token_settings = token_settings_response.json::<TokenSetting>()
        .await
        .unwrap();

    Ok(format!("{}{}{}{}", BEGIN_PUBLIC_KEY, token_settings.public_key, "\n", END_PUBLIC_KEY))
}


#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenSetting {
    pub realm: String,
    #[serde(rename = "public_key")]
    pub public_key: String,
    #[serde(rename = "token-service")]
    pub token_service: String,
    #[serde(rename = "account-service")]
    pub account_service: String,
    #[serde(rename = "tokens-not-before")]
    pub tokens_not_before: i64,
}