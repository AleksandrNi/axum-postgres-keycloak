use crate::error::app_error::{AppErrorBody, AppGenericError};

// body
fn integration_error_body(err: String) -> AppErrorBody {
    AppErrorBody::new(format!("Integration error occurred: '{}'", err), "appIntegrationError001")
}

fn integration_error_for_param_body(param: String) -> AppErrorBody {
    AppErrorBody::new(format!("Integration error occurred for param: '{}'", param), "appIntegrationError002")
}

fn integration_error_for_param_value_body(param: String, value: String) -> AppErrorBody {
    AppErrorBody::new(format!("Integration error occurred for param: '{}' value: '{}'", param, value), "appIntegrationError003")
}


pub struct AppIntegrationError;

impl AppIntegrationError {
    pub fn integration_error(err: String) -> AppGenericError {
        AppGenericError::Integration(integration_error_body(err))
    }

    pub fn integration_error_for_param(param: String) -> AppGenericError {
        AppGenericError::Integration(integration_error_for_param_body(param))
    }

    pub fn integration_error_for_param_value(param: String, value: String) -> AppGenericError {
        AppGenericError::Integration(integration_error_for_param_value_body(param, value))
    }
}