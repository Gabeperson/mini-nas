use std::path::PathBuf;

use actix_files::NamedFile;
use actix_web::HttpResponse;
use actix_web::{get, post, web, App, Either, HttpServer, Responder};

use actix_multipart::form::{tempfile::TempFile, MultipartForm, MultipartFormConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all("files").expect("Should be able to create files dir.");
    HttpServer::new(move || {
        App::new()
            .app_data(MultipartFormConfig::default().total_limit(5 * 1024 * 1024 * 1024)) // 5gb
            .service(get_file)
            .service(index)
            .service(random)
            .service(upload)
    })
    .bind(("0.0.0.0", 8080))?
    .workers(1)
    .run()
    .await
    .ok();

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
    println!("Got here");
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
    HttpResponse::TemporaryRedirect()
        .append_header((
            "Location",
            choice
                .to_str()
                .expect("Should be able to convert path to str."),
        ))
        .finish()
}

#[get("/files/{filename}")]
async fn get_file(path: web::Path<String>) -> actix_web::Result<impl Responder> {
    let path = path.into_inner();
    match NamedFile::open_async(&format!("files/{path}")).await {
        Ok(file) => Ok(Either::Left(file)),
        Err(_) => Ok(Either::Right(HttpResponse::NotFound().body("Not Found"))),
    }
}

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../web/index.html"))
}
