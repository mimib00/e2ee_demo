use std::{fs, usize};

use axum::{
    body::Body,
    extract::{Path, Request},
    http::StatusCode,
    middleware::Next,
    response::Response,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    rand_core::OsRng,
    RsaPrivateKey, RsaPublicKey,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// Load Private Key (for decrypting incoming requests)
fn load_private_key() -> RsaPrivateKey {
    let pem_content =
        fs::read_to_string("./certs/private.pem").expect("Failed to read private.pem");
    RsaPrivateKey::from_pkcs8_pem(&pem_content).expect("Failed to parse private key")
}

// Load Public Key (for encrypting responses)
fn load_public_key() -> RsaPublicKey {
    let pem_content = fs::read_to_string("./certs/public.pem").expect("Failed to read public.pem");
    RsaPublicKey::from_public_key_pem(&pem_content).expect("Failed to parse public key")
}

// Encrypt Response Data
fn encrypt(data: &str, public_key: &RsaPublicKey) -> String {
    let mut rng = OsRng;
    let encrypted_data = public_key
        .encrypt(&mut rng, rsa::Pkcs1v15Encrypt, data.as_bytes())
        .expect("Invalide data");

    STANDARD.encode(encrypted_data) // Base64 encode encrypted data
}

// Decrypt Incoming Request
fn decrypt(encrypted_data: &str, private_key: &RsaPrivateKey) -> Result<String, String> {
    let encrypted_bytes = STANDARD
        .decode(encrypted_data)
        .expect("Invalid base64 input");
    match private_key.decrypt(rsa::Pkcs1v15Encrypt, &encrypted_bytes) {
        Ok(decrypted_data) => {
            Ok(String::from_utf8(decrypted_data).expect("Invalid UTF-8 sequence"))
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn decrypt_requests(request: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let (parts, body) = request.into_parts();

    let encrypted_body = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // 🔹 Convert bytes to string
    let encrypted_string =
        String::from_utf8(encrypted_body.to_vec()).map_err(|_| StatusCode::BAD_REQUEST)?;

    let private_key = load_private_key();

    // 🔹 Decrypt the request body (Replace `decrypt` with your actual function)
    if let Ok(decrypted_body) = decrypt(&encrypted_string, &private_key) {
        // 🔹 Deserialize to `serde_json::Value`
        let json_value: Value =
            serde_json::from_str(&decrypted_body).map_err(|_| StatusCode::BAD_REQUEST)?;

        // 🔹 Attach decrypted JSON to request extensions
        let mut req = Request::from_parts(parts, Body::from(decrypted_body));
        req.extensions_mut().insert(Json(json_value));

        let response = next.run(req).await;

        return Ok(response);
    }

    let req = Request::from_parts(parts.clone(), Body::default());
    let response = next.run(req).await;

    return Ok(response);
}

async fn generate_request() -> String {
    let public_key = load_public_key();
    let msg = Message {
        msg: "Hello World".to_string(),
    };

    let encrypted_data = encrypt(serde_json::to_string(&msg).unwrap().as_str(), &public_key);
    encrypted_data
}

#[derive(Serialize, Deserialize)]
pub struct Message {
    msg: String,
}

async fn show_request(Json(body): Json<Message>) -> String {
    format!("Received decrypted message: {}", body.msg)
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/data", get(generate_request))
        .route("/data/show", post(show_request))
        .layer(axum::middleware::from_fn(decrypt_requests));

    // run our app with hyper, listening globally on port 8080
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
