use service::user::user_dto::UserDto;
use utils::core::keycloak::TokenBearerOnlyPayload;

pub struct UserPayload {
    // user_dto: UserDto,
    token_payload: TokenBearerOnlyPayload,
}

impl UserPayload {
    pub fn new(token_payload: TokenBearerOnlyPayload) -> Self {
        UserPayload {  token_payload }
    }
}

impl UserPayload {
    // pub fn get_user_dto(&self) -> &UserDto {
    //     &self.user_dto
    // }
    pub fn get_token_payload(&self) -> &TokenBearerOnlyPayload {
        &self.token_payload
    }
}