use serde_derive::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenPayload {
    // exp: i64,
    // iat: i64,
    // #[serde(rename = "auth_time")]
    // auth_time: i64,
    // jti: String,
    // iss: String,
    // aud: Vec<String>,
    // sub: String,
    // typ: String,
    // azp: String,
    // #[serde(rename = "session_state")]
    // session_state: String,
    // acr: String,
    // #[serde(rename = "allowed-origins")]
    // allowed_origins: Vec<String>,
    #[serde(rename = "realm_access")]
    realm_access: RealmAccess,
    #[serde(rename = "resource_access")]
    resource_access: ResourceAccess,
    scope: String,
    sid: String,
    #[serde(rename = "email_verified")]
    email_verified: bool,
    name: String,
    #[serde(rename = "preferred_username")]
    preferred_username: String,
    #[serde(rename = "given_name")]
    given_name: String,
    #[serde(rename = "family_name")]
    family_name: String,
    email: String,
}

impl TokenPayload {
    pub fn get_name(&self) -> &str {
        &self.name
    }
    pub fn get_family(&self) -> &str {
        &self.family_name
    }
    pub fn get_roles(&self) -> &Vec<String> {
        &self.realm_access.roles
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RealmAccess {
    roles: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResourceAccess {
    #[serde(rename = "service-realm-front-clientId")]
    service_realm_front_client_id: ServiceRealmFrontClientId,
    #[serde(rename = "service-realm-back-clientId")]
    service_realm_back_client_id: ServiceRealmBackClientId,
    account: Account,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceRealmFrontClientId {
    roles: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceRealmBackClientId {
    roles: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Account {
    roles: Vec<String>,
}