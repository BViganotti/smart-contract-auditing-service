use actix_web::{App, HttpServer, http};
use actix_cors::Cors;

mod models;
mod routes;
mod services;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let cors = Cors::permissive();  // This is a simpler way to enable all CORS

        App::new()
            .wrap(cors)
            .configure(routes::configure_routes)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
