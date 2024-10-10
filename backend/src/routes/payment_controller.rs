use crate::services::payment_service;
use actix_web::Responder;

pub async fn process_payment() -> impl Responder {
    payment_service::process_payment().await
}
