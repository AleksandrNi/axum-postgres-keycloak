use utils::core::dto::keycloak_token::TokenPayload;

pub struct UserPayload {
    // user_dto: UserDto,
    token_payload: TokenPayload,
}

impl UserPayload {
    pub fn new(token_payload: TokenPayload) -> Self {
        UserPayload {  token_payload }
    }
}

impl UserPayload {
    // pub fn get_user_dto(&self) -> &UserDto {
    //     &self.user_dto
    // }
    pub fn get_token_payload(&self) -> &TokenPayload {
        &self.token_payload
    }
}