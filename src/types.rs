use crate::*;
#[derive(Serialize)]
pub struct AccessToken {
    pub id: String,
    pub name: String,
    pub access_token: String,
    pub email: String
}

// the input to our `create_user` handler
#[derive(Deserialize)]
pub struct CreateUser {
    pub username: String,
}

// the output to our `create_user` handler
#[derive(Serialize)]
pub struct User {
    pub id: String,
    pub permalink: String,
    pub username: String,
    pub full_name: String
}

#[derive(Debug, Deserialize)]
pub struct AuthPayload {
    pub client_id: String,
    pub client_secret: String,
    pub code: String,
    pub grant_type: String,
}