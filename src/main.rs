use std::path::PathBuf;

use actix_files::NamedFile;
use actix_web::HttpResponse;
use actix_web::{get, post, web, App, Either, HttpServer, Responder};

use actix_multipart::form::{tempfile::TempFile, MultipartForm, MultipartFormConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting server.");
    std::fs::create_dir_all("files").expect("Should be able to create files dir.");
    HttpServer::new(move || {
        App::new()
            .app_data(MultipartFormConfig::default().total_limit(5 * 1024 * 1024 * 1024)) // 5gb
            .service(get_file)
            .service(index)
            .service(random)
            .service(upload)
            .service(contents)
            .service(player)
            .service(videojs_css)
            .service(videojs_js)
    })
    .bind(("0.0.0.0", 8080))?
    .workers(1)
    .run()
    .await
    .ok();
    println!("Server stopped. Exiting...");
    Ok(())
}

#[derive(Debug, MultipartForm)]
struct UploadForm {
    #[multipart(rename = "file")]
    files: Vec<TempFile>,
}

#[post("/")]
async fn upload(
    MultipartForm(form): MultipartForm<UploadForm>,
) -> Result<impl Responder, actix_web::Error> {
    println!("Received upload request.");
    for f in form.files {
        let path = format!("./files/{}", f.file_name.unwrap());
        f.file.persist(path).unwrap();
    }
    Ok(HttpResponse::Ok())
}

#[get("/random")]
async fn random() -> impl Responder {
    use rand::seq::SliceRandom;
    let readdir = std::fs::read_dir("files/").expect("Should have access to file in local dir.");
    let files = readdir
        .map(|i| i.expect("Should have access to file in local dir.").path())
        .collect::<Vec<PathBuf>>();
    let choice = files
        .choose(&mut rand::thread_rng())
        .expect("Should have at least one file");
    let stringified = choice
        .to_str()
        .expect("Should be able to convert path to str.");
    println!("Received `/random` request. Redirecting to `{stringified}`");
    HttpResponse::TemporaryRedirect()
        .append_header((
            "Location",
            format!("/player/{}", stringified),
        ))
        .finish()
}

#[get("/files/{filename}")]
async fn get_file(path: web::Path<String>) -> actix_web::Result<impl Responder> {
    let path = path.into_inner();
    println!("Received `/files/{path}` request.");
    match NamedFile::open_async(&format!("files/{path}")).await {
        Ok(file) => Ok(Either::Left(file)),
        Err(_) => Ok(Either::Right(HttpResponse::NotFound().body("Not Found"))),
    }
}

#[get("/player/{filename:.*}")]
async fn player(filename: web::Path<String>) -> impl Responder {
    println!("Received `/player/{filename}` request.");
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../web/player.html").replace("INSERT SOURCE HERE", &format!("/{}", filename.into_inner())))
}

#[get("/")]
async fn index() -> impl Responder {
    println!("Received `/` request.");
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../web/index.html"))
}

#[get("/videojs.css")]
async fn videojs_css() -> impl Responder {
    println!("Received `/videojs.css` request.");
    HttpResponse::Ok()
        .content_type("text/css; charset=utf-8")
        .body(include_str!("../web/videojs.css"))
}

#[get("/videojs.js")]
async fn videojs_js() -> impl Responder {
    println!("Received `/videojs.js` request.");
    HttpResponse::Ok()
        .content_type("text/javascript; charset=utf-8")
        .body(include_str!("../web/videojs.js"))
}

#[get("/contents")]
async fn contents() -> impl Responder {
    println!("Received `/contents` request.");
    let body = {
        let mut body = String::new();
        let readdir = std::fs::read_dir("files/").expect("Should have access to file in local dir.");
        let mut files = readdir
        .map(|i| i.expect("Should have access to file in local dir.").path().to_string_lossy().to_string())
        .collect::<Vec<_>>();
        files.sort_by(|a, b| a.trim().to_lowercase().cmp(&b.trim().to_lowercase()));
        for s in files {
            let link = format! {
                "<a href=\"/player/{s}\">{s}</a><br>",
            };
            body.push_str(&link);
        }
        if body.is_empty() {
            body = "No files uploaded yet.".to_string();
        }
        body
    };
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body)
}
