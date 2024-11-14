// File: /smart-contract-auditing-service/smart-contract-auditing-service/backend/src/routes/mod.rs

use actix_web::web;

mod audit_controller;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api").route("/audit", web::post().to(audit_controller::audit_contract)),
    );
}

// End of file
