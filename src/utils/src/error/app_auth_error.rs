use crate::error::app_error::{AppErrorBody, AppGenericError};

// body
fn auth_error_body(err: String) -> AppErrorBody {
    AppErrorBody::new(format!("Auth error occurred: '{}'", err), "appAuthError001")
}

fn auth_error_for_param_body(param: String) -> AppErrorBody {
    AppErrorBody::new(format!("Auth error occurred for param: '{}'", param), "appAuthError002")
}

fn auth_error_for_param_value_body(param: String, value: String) -> AppErrorBody {
    AppErrorBody::new(format!("Auth error occurred for param: '{}' value: '{}'", param, value), "appAuthError003")
}


pub struct AppAuthError;

impl AppAuthError {
    pub fn auth_error(err: String) -> AppGenericError {
        AppGenericError::Auth(auth_error_body(err))
    }

    pub fn auth_error_for_param(param: String) -> AppGenericError {
        AppGenericError::Auth(auth_error_for_param_body(param))
    }

    pub fn auth_error_for_param_value(param: String, value: String) -> AppGenericError {
        AppGenericError::Auth(auth_error_for_param_value_body(param, value))
    }
}