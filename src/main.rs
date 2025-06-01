use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, web};
use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize)]
struct Reservation {
    reservation_id: String,
    user_id: String,
    item_details: String,
}

// Simulate a simple in-memory database
// Key: user_id (String), Value: Vec<Reservation>
type Db = Arc<DashMap<String, Vec<Reservation>>>;

fn populate_mock_db(db: &Db) {
    let user1_reservations = vec![
        Reservation {
            reservation_id: "res101".to_string(),
            user_id: "user1".to_string(),
            item_details: "Resource Alpha".to_string(),
        },
        Reservation {
            reservation_id: "res102".to_string(),
            user_id: "user1".to_string(),
            item_details: "Resource Beta".to_string(),
        },
    ];
    db.insert("user1".to_string(), user1_reservations);

    let user2_reservations = vec![Reservation {
        reservation_id: "res201".to_string(),
        user_id: "user2".to_string(),
        item_details: "Resource Gamma".to_string(),
    }];
    db.insert("user2".to_string(), user2_reservations);
}

// --- Vulnerable Handler ---
// This handler takes a user ID from the URL path and fetches reservations.
// It is vulnerable because it does not check if the requester is authorized
// to view reservations for the given user ID.
async fn get_reservations_vulnerable(
    user_id_from_path: web::Path<String>, // Extracts the {user_id_from_path} segment
    db: web::Data<Db>,
) -> impl Responder {
    let id = user_id_from_path.into_inner();

    // Directly use the ID from the path to query the mock database.
    match db.get(&id) {
        Some(reservations_entry) => {
            let reservations = reservations_entry.value();
            HttpResponse::Ok().json(reservations)
        }
        None => {
            // If the user ID doesn't exist, return an empty array.
            HttpResponse::Ok().json(Vec::<Reservation>::new())
        }
    }
}

// --- Secure Handler ---
// This handler mitigates the BOLA vulnerability by checking authorization.
// It simulates fetching an authenticated user's ID from a request header
// and compares it against the user ID requested in the URL path.
async fn get_reservations_secure(
    req: HttpRequest, // We need HttpRequest to access headers
    requested_id_from_path: web::Path<String>,
    db: web::Data<Db>,
) -> impl Responder {
    let requested_id = requested_id_from_path.into_inner();

    // Simulate fetching the authenticated user's ID from a request header.
    // In a real application, this would come from a proper authentication system.
    let current_user_id_header = req.headers().get("X-Authenticated-User-ID");
    let current_user_id: String;

    match current_user_id_header {
        Some(header_value) => match header_value.to_str() {
            Ok(id_str) => current_user_id = id_str.to_string(),
            Err(_) => {
                return HttpResponse::BadRequest()
                    .body("Invalid X-Authenticated-User-ID header format.");
            }
        },
        None => {
            return HttpResponse::Unauthorized().body("Missing X-Authenticated-User-ID header.");
        }
    }

    // Authorization check: The authenticated user's ID must match the requested ID.
    if current_user_id != requested_id {
        return HttpResponse::Forbidden().body(format!(
            "Unauthorized access. You (User '{}') cannot access reservations for User '{}'.",
            current_user_id, requested_id
        ));
    }

    // If authorized, fetch reservations using the authenticated (and verified) user's ID.
    match db.get(&current_user_id) {
        Some(reservations_entry) => {
            let reservations = reservations_entry.value();
            HttpResponse::Ok().json(reservations)
        }
        None => HttpResponse::Ok().json(Vec::<Reservation>::new()),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mock_db = Arc::new(DashMap::<String, Vec<Reservation>>::new());
    populate_mock_db(&mock_db);
    let app_db = web::Data::new(mock_db);

    println!("🦀 Simple BOLA Server running at http://127.0.0.1:8080");
    println!("   Vulnerable Endpoint: GET /vulnerable/users/{{user_id}}");
    println!(
        "   Secure Endpoint:     GET /secure/users/{{user_id}} (requires X-Authenticated-User-ID header)"
    );

    HttpServer::new(move || {
        App::new()
            .app_data(app_db.clone())
            .route(
                "/vulnerable/users/{user_id_from_path}",
                web::get().to(get_reservations_vulnerable),
            )
            .route(
                "/secure/users/{user_id_from_path}",
                web::get().to(get_reservations_secure),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
