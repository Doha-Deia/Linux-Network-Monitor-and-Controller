use std::sync::{Arc, Mutex};

use axum::{routing::get, Json, Router};
use tower_http::services::ServeDir;

use crate::aggregator::Aggregator;

pub fn create_app(agg: Arc<Mutex<Aggregator>>) -> Router {
    Router::new()
        .route("/api/summary", get({
            let agg = agg.clone();
            move || async move {
                let snapshot = agg.lock().unwrap().snapshot();
                Json(snapshot)
            }
        }))
        .nest_service("/", ServeDir::new("gui"))
}