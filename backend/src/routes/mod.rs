use actix_web::web;

mod audit_controller;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api").route("/audit", web::post().to(audit_controller::audit_contract)),
    );
}
