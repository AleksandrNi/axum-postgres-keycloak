use std::collections::HashMap;
use axum::body::HttpBody;
use bcrypt::verify;
use reqwest::{Body, RequestBuilder, StatusCode};
use serde_derive::Deserialize;
use serde_derive::Serialize;
use tracing::{error, info};
use crate::error::app_error::AppGenericError;
use crate::error::app_integration_error::AppIntegrationError;
use crate::error::app_web_error::AppWebError;
use rust_keycloak::jwt;

use jsonwebtoken::{Validation, Algorithm, DecodingKey, decode, TokenData};
use crate::error::app_auth_error::AppAuthError;


// IMPLEMENTED
// 1. KEYCLOAK CLIENT BEARER-ONLY
// 2. KEYCLOAK CLIENT CONFIDENTIAL

// KEYcLOAK BEARER-ONLY CLIENT IMPLEMENTATION  BLOCK START

// client bearer-only
pub async fn get_keycloak_token_claims(token: &str) -> Result<TokenBearerOnlyPayload, AppGenericError> {
    let client = reqwest::Client::new();

    let keycloak_auth_realm_url = std::env::var("KEYCLOAK_AUTH_REALM")
        .unwrap_or_else(|_| panic!("KEYCLOAK_AUTH_REALM must be set!"));

    let token_settings_response = client
        .get(keycloak_auth_realm_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        // .body(body_params)
        .send()
        .await
        .map_err(|err| {
            AppIntegrationError::integration_error(err.to_string())
        })
        .unwrap();

    if !token_settings_response.status().is_success() {
        error!("status {}", &token_settings_response.status());
        if token_settings_response.status().is_client_error() {
            return Err(AppIntegrationError::integration_error("client error".to_string()))
        } else {
            return Err(AppIntegrationError::integration_error("server error".to_string()))
        }
    }

    let token_settings = token_settings_response.json::<TokenSetting>()
        .await
        .unwrap();

    let public_key = format!("{}{}{}{}", "-----BEGIN PUBLIC KEY-----\n", token_settings.public_key, "\n", "-----END PUBLIC KEY-----\n");

    let decoding_key = DecodingKey::from_rsa_pem(&public_key[..].as_bytes()).unwrap();

    let token_payload = match decode::<TokenBearerOnlyPayload>(
        token,
        &decoding_key,
        &Validation::new(Algorithm::RS256)
    ) {
        Ok(c) => c.claims,
        Err(err) => {

            error!("ERROR --> : {}", &err);
            return Err(AppAuthError::auth_error(err.to_string()));
        }
    };

    Ok(token_payload)
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



#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenBearerOnlyPayload {
    pub exp: i64,
    pub iat: i64,
    #[serde(rename = "auth_time")]
    pub auth_time: i64,
    pub jti: String,
    pub iss: String,
    pub aud: Vec<String>,
    pub sub: String,
    pub typ: String,
    pub azp: String,
    pub nonce: String,
    #[serde(rename = "session_state")]
    pub session_state: String,
    pub acr: String,
    #[serde(rename = "allowed-origins")]
    pub allowed_origins: Vec<String>,
    #[serde(rename = "realm_access")]
    pub realm_access: RealmAccess,
    #[serde(rename = "resource_access")]
    pub resource_access: ResourceAccess,
    pub scope: String,
    pub sid: String,
    #[serde(rename = "email_verified")]
    pub email_verified: bool,
    pub name: String,
    #[serde(rename = "preferred_username")]
    pub preferred_username: String,
    #[serde(rename = "given_name")]
    pub given_name: String,
    #[serde(rename = "family_name")]
    pub family_name: String,
    pub email: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RealmAccess {
    pub roles: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceAccess {
    #[serde(rename = "service-realm-front-clientId")]
    pub service_realm_front_client_id: ServiceRealmFrontClientId,
    #[serde(rename = "service-realm-back-clientId")]
    pub service_realm_back_client_id: ServiceRealmBackClientId,
    pub account: Account,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceRealmFrontClientId {
    pub roles: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceRealmBackClientId {
    pub roles: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub roles: Vec<String>,
}

// KEYcLOAK BEARER-ONLY CLIENT IMPLEMENTATION  BLOCK END



// KEYcLOAK CONFIDENTIAL CLIENT IMPLEMENTATION BLOCK

// client confidential

const KEYCLOAK_CLIENT_SECRET_KEY: &str = "client_secret";
const KEYCLOAK_CLIENT_ID_KEY: &str = "client_id";
const KEYCLOAK_USERNAME_KEY: &str = "username";
const KEYCLOAK_TOKEN_KEY: &str = "token";

pub async fn get_keycloak_token_confidential(token: &str) -> Result<TokenConfidentialPayload, AppGenericError> {
    let keycloak_url = std::env::var("KEYCLOAK_URL").unwrap_or_else(|_| panic!("KEYCLOAK_URL must be set!"));
    let realm = std::env::var("KEYCLOAK_REALM").unwrap_or_else(|_| panic!("KEYCLOAK_URL must be set!"));
    let client_id = std::env::var("KEYCLOAK_CLIENT_ID").unwrap_or_else(|_| panic!("KEYCLOAK_CLIENT_ID must be set!"));
    let client_secret = std::env::var("KEYCLOAK_CLIENT_SECRET").unwrap_or_else(|_| panic!("KEYCLOAK_CLIENT_SECRET must be set!"));
    let username = std::env::var("KEYCLOAK_USERNAME").unwrap_or_else(|_| panic!("KEYCLOAK_USERNAME must be set!"));

    // GET TOKEN
    // how to get token in postman
    // 1. type: Oauth 2.0
    // 2. Add auth data to: Request headers
    // 3. Grant type: Authorization code (with PKCE)
    // 5. Callback URL: http://localhost:8080 (backend service url)
    // 6. Auth URL: http://127.0.0.1:8180/auth/realms/your-realm/protocol/openid-connect/auth (keycloak url)
    // 7. Access Token URL: http://127.0.0.1:8180/auth/realms/your-realm/protocol/openid-connect/token
    // 8. Client ID: app-realm-client-confidetial
    // 9. Client Secret: 7lnlFslMSdLBhCcHuNhFszvP0hwCYrn0
    // 10. Code Challenge Method: SHA256
    // -> press button "Get new Access token"


    // curl --location --request GET 'http://127.0.0.1:8180/auth/realms/app-external/protocol/openid-connect/token'


    // INTORSPECT TOKEN

    // how to get client secret for confidential keycloak client -> Clients -> Client (confidential) -> Credentials -> Secret

    // curl --location --request POST 'http://127.0.0.1:8180/auth/realms/your-realm/protocol/openid-connect/token/introspect' \
    // --header 'Content-Type: application/x-www-form-urlencoded' \
    //     --data-urlencode 'client_secret=7lnlFslMSdLBhCcHuNhFszvP0hwCYrn0' \
    //     --data-urlencode 'client_id=app-realm-client-confidential' \
    //     --data-urlencode 'username=user' \
    //     --data-urlencode 'token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJWa3V6OVZrMTBDaDhzbWVHa1R5Rkp4LXB4enVuMGItTjd6RlUtY3o0MkR3In0.eyJleHAiOjE2NzcwNjk2ODcsImlhdCI6MTY3NzA2OTM4NywiYXV0aF90aW1lIjoxNjc3MDY5Mzg2LCJqdGkiOiI5NGZmMzFiMy1mYTQyLTRjMTQtOTdlOS03ZTRlNDM2MzVmMzgiLCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjgxODAvYXV0aC9yZWFsbXMvYXBwLXJlYWxtIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImI4ZGYwOWQzLWNjMDEtNGMwZC1hZjQyLWI0MGExYmQwZmYyOCIsInR5cCI6IkJlYXJlciIsImF6cCI6ImFwcC1yZWFsbS1jbGllbnQtcHViIiwic2Vzc2lvbl9zdGF0ZSI6IjQwYTkyNTJmLTRiM2YtNDlhNC05NGFkLTUyYjhiMmJhMDgyZCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiKiJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiIsImRlZmF1bHQtcm9sZXMtYXBwLXJlYWxtIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwic2lkIjoiNDBhOTI1MmYtNGIzZi00OWE0LTk0YWQtNTJiOGIyYmEwODJkIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJuYW1lIjoiU2FzaGEgTmlraXRpbiIsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3QiLCJnaXZlbl9uYW1lIjoiU2FzaGEiLCJmYW1pbHlfbmFtZSI6Ik5pa2l0aW4iLCJlbWFpbCI6InRlc3RAdGVzdC5ydSJ9.CmY6S_RsRTxfNz-o-uaZ_sq6uxzBhzWCIesLJKzfPXRIDAg9oXXq-NgLDWUdM96j-nhdF530TtJVxGNTXZvRXNU7lhDYBMiU1csxMGAmPiSMe7XFYX8BFghZzDTyTcOVOXkoqaeCYrW0KHNz_VHVoEsVzveZLWVPlaaPQiLvyQrsWZx2p8-gUitu7S27exfp6HcazZu-ujJQIyo_LYNqFykidF8IFJ3Qr-2eVCWFNNK0nxgfDaGfrZggHQYoBQUBq8xsFdtoC0sdMIZ2iVFY_7uBPQt-lbPTUony8-_IXMIRhkkZCTmKcUQo_Luj1yGPDeVWaG0cCU9yxkbRlavzng'

    let url = format!("{}/auth/realms/{}/protocol/openid-connect/token/introspect", keycloak_url, realm);
    info!("keycloak url = {}", &url);
    let client = reqwest::Client::new();
    let mut params = HashMap::new();

    let token = token.to_string();
    params.insert(KEYCLOAK_CLIENT_SECRET_KEY, &client_secret);
    params.insert(KEYCLOAK_CLIENT_ID_KEY, &client_id);
    params.insert(KEYCLOAK_USERNAME_KEY, &username);
    params.insert(KEYCLOAK_TOKEN_KEY, &token);

    let body_params = serde_urlencoded::to_string(params).unwrap();
    info!("body_params = {}", &body_params);
    let response = client
        .post(url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body_params)
        .send()
        .await
        .map_err(|e| {
            error!("ERROR: {}", &e);
            AppIntegrationError::integration_error(e.to_string())
        })
        .unwrap();
    info!("{:?}", &response);
    info!("{:?}", &response.status());
    if !response.status().is_success() {
        if response.status().is_client_error() {
            return Err(AppIntegrationError::integration_error("client error".to_string()))
        } else {
            return Err(AppIntegrationError::integration_error("server error".to_string()))
        }
    }

        // let res = response
        // .text()
        // .await
        // .expect("failed to get payload");

    // println!("rest = {}", res);

     let jwt_body = response.json::<TokenConfidentialPayload>()
        .await
        .unwrap();

    Ok(jwt_body)
}


#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenConfidentialPayload {
    pub exp: i64,
    pub iat: i64,
    #[serde(rename = "auth_time")]
    pub auth_time: i64,
    pub jti: String,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub typ: String,
    pub azp: String,
    #[serde(rename = "session_state")]
    pub session_state: String,
    pub name: String,
    #[serde(rename = "given_name")]
    pub given_name: String,
    #[serde(rename = "family_name")]
    pub family_name: String,
    #[serde(rename = "preferred_username")]
    pub preferred_username: String,
    pub email: String,
    #[serde(rename = "email_verified")]
    pub email_verified: bool,
    pub acr: String,
    #[serde(rename = "realm_access")]
    pub realm_access: RealmAccess,
    #[serde(rename = "resource_access")]
    pub resource_access: ResourceAccess,
    pub scope: String,
    pub sid: String,
    #[serde(rename = "client_id")]
    pub client_id: String,
    pub username: String,
    pub active: bool,
}

// KEYcLOAK CONFIDENTIAL CLIENT IMPLEMENTATION BLOCK END
