mod types;

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use axum::{routing::{get, post}, extract::{RequestParts}, http::StatusCode, response::IntoResponse, Json, Router, middleware, response};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::SystemTime;
use async_graphql::http::GraphiQLSource;
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::body::{Body, Bytes};
use axum::extract::{Extension, Path, Query, RawQuery};
use axum::http::header::CONTENT_TYPE;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{Redirect, Response};
use chrono::Utc;
use tracing::{Level, info};
use tracing_subscriber::{filter, fmt};
use tracing_subscriber::fmt::Layer;
use tracing_subscriber::fmt::time::{LocalTime, OffsetTime};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use crate::types::{AccessToken, AuthPayload, User};
use iter_tools::*;

#[tokio::main]
async fn main() {
    // let local = OffsetTime::local_rfc_3339().unwrap();
    // tracing_subscriber::fmt::SubscriberBuilder::default().with_timer(local).init();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "discourse_server=debug,example_print_request_response=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        // `POST /users` goes to `create_user`
        .route("/oauth", get(oauth))
        .route("/token", post(token))
        .route("/user", get(user))
        .layer(middleware::from_fn(print_request_response));

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("listening on http://localhost:5906");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}

async fn oauth(
    RawQuery(query): RawQuery,
    Query(params): Query<HashMap<String, String>>
) -> impl IntoResponse {
    info!("oauth, {:?}", query);

    let time = Utc::now().timestamp().to_string();

    // "123"
    dbg!(&time);
    // let time = "1664185855";

    let redirect_url = format!("http://localhost:3000/auth/oauth2_basic/callback?code={}&state={}",time, params.get("state").unwrap().to_string());

    info!("redirect to {}", &redirect_url);
    Redirect::to(&redirect_url)
}

async fn token(body: String) -> impl IntoResponse {
    info!("token, body :{:?}", body);

    let params: HashMap<String, String> = body.split("&").map(|e| {
        let split = e.split("=").collect_vec();
        (split.get(0).unwrap().to_string(), split.get(1).unwrap().to_string())
    }).collect();
    info!("token, params from body :{:?}", params);

    let code = params.get("code").unwrap();

    let token = AccessToken {
        id: code.clone(),
        name: code.clone(),
        access_token: code.clone(),
        email: format!("{}@qq.com", code).to_string()
    };
    (StatusCode::OK, Json(token))
}

async fn user(RawQuery(query): RawQuery) -> impl IntoResponse {

    info!("user, {:?}", query);

    let user = User {
        id: "112".to_string(),
        permalink: "permalink".to_string(),
        username: "username".to_string(),
        full_name: "full name".to_string()
    };
    (StatusCode::OK, Json(user))
}



async fn print_request_response(
    req: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (parts, body) = req.into_parts();
    let bytes = buffer_and_print("request", body).await?;
    let req = Request::from_parts(parts, Body::from(bytes));

    let res = next.run(req).await;

    let (parts, body) = res.into_parts();
    let bytes = buffer_and_print("response", body).await?;
    let res = Response::from_parts(parts, Body::from(bytes));

    Ok(res)
}

async fn buffer_and_print<B>(direction: &str, body: B) -> Result<Bytes, (StatusCode, String)>
    where
        B: axum::body::HttpBody<Data = Bytes>,
        B::Error: std::fmt::Display,
{
    let bytes = match hyper::body::to_bytes(body).await {
        Ok(bytes) => bytes,
        Err(err) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("failed to read {} body: {}", direction, err),
            ));
        }
    };

    if let Ok(body) = std::str::from_utf8(&bytes) {
        tracing::debug!("{} body = {:?}", direction, body);
    }

    Ok(bytes)
}

#[test]
fn parseBody() {
    let a = "client_id=1a6c914bf0162e394fb5ec30959828340c67efa7671b7a804c9d577d48aa3ec2&client_secret=0afa1f8cf7549e439ac5edbd99fd83b2b5ba9a1b68031cbc2bb2cf36530d94f7&code=xs1b.test&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fauth%2Foauth2_basic%2Fcallback";
    let params: HashMap<String, String> = a.split("&").map(|e| {
        let split = e.split("=").collect_vec();
        (split.get(0).unwrap().to_string(), split.get(1).unwrap().to_string())
    }).collect();
    dbg!(params);
}