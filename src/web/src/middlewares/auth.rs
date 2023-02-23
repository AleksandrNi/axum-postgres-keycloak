use axum::headers::Authorization;
use axum::headers::authorization::Bearer;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::{Json, TypedHeader};
use tracing::{info, warn};
use utils::core::keycloak::get_keycloak_token_claims;
use utils::error::app_error::AppGenericError;
use crate::middlewares::dto::user::UserPayload;
use crate::utils::error::{AppResponseError, AppResponseErrorBody};
use utils::error::app_error::AppGenericErrorTrait;
use axum::response::IntoResponse;


pub async fn guard<B>(
    TypedHeader(token): TypedHeader<Authorization<Bearer>>,
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, Response> {
    let jwt_token = token.token().to_owned();

    let result = get_keycloak_token_claims(&jwt_token[..]).await;

    if let Err(app_generic_error) = result {
        warn!("{:?}", app_generic_error);
        return match app_generic_error {
            AppGenericError::Auth(err) => Err((StatusCode::UNAUTHORIZED,
                                               Json(AppResponseErrorBody::from_app_response_error(AppResponseError::new(
                                                   StatusCode::UNAUTHORIZED,
                                                   err.get_code(),
                                                   err.get_message(),
                                               )))).into_response() as Response
            ),
            AppGenericError::Integration(err) => Err((StatusCode::INTERNAL_SERVER_ERROR,
                                                      Json(AppResponseErrorBody::from_app_response_error(AppResponseError::new(
                                                          StatusCode::INTERNAL_SERVER_ERROR,
                                                          err.get_code(),
                                                          err.get_message(),
                                                      )))).into_response() as Response
            ),
            AppGenericError::Repository(err) => Err((StatusCode::INTERNAL_SERVER_ERROR,
                                                     Json(AppResponseErrorBody::from_app_response_error(AppResponseError::new(
                                                         StatusCode::INTERNAL_SERVER_ERROR,
                                                         err.get_code(),
                                                         err.get_message(),
                                                     )))).into_response() as Response
            ),
            AppGenericError::Service(err) => Err((StatusCode::INTERNAL_SERVER_ERROR,
                                                  Json(AppResponseErrorBody::from_app_response_error(AppResponseError::new(
                                                      StatusCode::INTERNAL_SERVER_ERROR,
                                                      err.get_code(),
                                                      err.get_message(),
                                                  )))).into_response() as Response
            ),
            AppGenericError::Web(err) => Err((StatusCode::INTERNAL_SERVER_ERROR,
                                              Json(AppResponseErrorBody::from_app_response_error(AppResponseError::new(
                                                  StatusCode::INTERNAL_SERVER_ERROR,
                                                  err.get_code(),
                                                  err.get_message(),
                                              )))).into_response() as Response
            ),
        };
    } else {
        let token_payload = result.unwrap();
        info!("token_payload = {:?}", token_payload);
        req.extensions_mut().insert(UserPayload::new(token_payload));
    }


    Ok(next.run(req).await)
}
