use crate::models::SmartContract;
use crate::services::audit_service::AuditService;
use actix_multipart::Multipart;
use actix_web::{HttpResponse, Responder};
use futures::{StreamExt, TryStreamExt};
use uuid::Uuid;

pub async fn audit_contract(mut payload: Multipart) -> impl Responder {
    let audit_service = AuditService::new();
    let mut contract_code = String::new();

    // Process the multipart stream
    while let Ok(Some(mut field)) = payload.try_next().await {
        while let Some(chunk) = field.next().await {
            let data = chunk.unwrap();
            contract_code.push_str(std::str::from_utf8(&data).unwrap());
        }
    }

    // Create a SmartContract instance
    let contract = SmartContract {
        id: Uuid::new_v4().to_string(),
        code: contract_code,
    };
    //println!("audit_controller: Contract code: {}", contract.code);

    // Perform the audit
    let result = audit_service.audit_contract(contract);

    HttpResponse::Ok().json(result)
}
