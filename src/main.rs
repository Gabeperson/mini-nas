#![feature(once_cell)]
use std::collections::HashMap;
use std::fs::canonicalize;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use actix_files::NamedFile;
use actix_web::web::Json;
use actix_web::{HttpResponse, HttpRequest, HttpMessage};
use actix_web::{get, post, web, App, Either, HttpServer, Responder, cookie::Key};

use actix_multipart::form::{tempfile::TempFile, MultipartForm, MultipartFormConfig};

use rand::Rng;
use rand::distributions::{Alphanumeric, DistString};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_identity::{Identity, IdentityMiddleware};
use std::sync::{OnceLock, RwLock, Mutex};
use serde::{Serialize, Deserialize};

const DEFAULT_USER_LIMIT: usize = 1000 * 1000 * 1000 * 10; // 10gb
const CONFIG_PATH: &'static str = "config/";
const FILES_DIR: &'static str = "files";

#[derive(Serialize, Deserialize, Clone, Debug)]
struct UserData {
    max_data: usize,
    password: String,
}

impl UserData {
    fn new(p: String) -> Self {
        Self {
            max_data: DEFAULT_USER_LIMIT,
            password: p,
        }
    }
}

fn user_timeout() -> &'static Mutex<HashMap<String, Instant>> {
    static USER_TIMEOUT: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    USER_TIMEOUT.get_or_init(|| Mutex::new(HashMap::new()))
}


#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Users {
    users: HashMap<String, UserData>,
}

impl Users {
    fn save(&self) {
        std::fs::write(format!("{CONFIG_PATH}users.json"), serde_json::to_string(self).unwrap()).expect("Failed to write to config file.");
    }

    fn read_or_empty() -> Self {
        match std::fs::read_to_string(format!("{CONFIG_PATH}users.json")) {
            Ok(s) => serde_json::from_str(&s).unwrap(),
            Err(_) => Self::default(),
        }
    }
}

fn users() -> &'static RwLock<Users> {
    static USERS: OnceLock<RwLock<Users>> = OnceLock::new();
    USERS.get_or_init(|| RwLock::new(Users::read_or_empty()))
}

fn count_size(path: &str) -> u128 {
    use walkdir::WalkDir;
    let mut calc = 0;
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if let Ok(m) = entry.metadata() {
            calc += m.len() as u128;
        }
    }
    calc
}



fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(CONFIG_PATH).ok();
    let _tokio_handle = std::thread::spawn(|| {
        tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main())
    });
    println!("Welcome to the NAS console. Type `help` for a list of commands.");
    loop {
        print!("\nNAS Console >> ");
        std::io::stdout().flush().ok();
        let mut buffer = String::new();
        std::io::stdin().read_line(&mut buffer)?;
        let buffer = buffer.trim();
        println!("");
        let mut split = buffer.split(" ");
        // just unwrap here because split's first should always exist.
        match split.next().unwrap() {
            "adduser" | "add" => {
                let (username, password) = match (split.next(), split.next()) {
                    (Some(username), Some(password)) => (username, password),
                    _ => {
                        println!("Invalid arguments. The `adduser` command has the syntax `adduser <username> <password>`.");
                        continue;
                    }
                };
                if !username.chars().all(char::is_alphanumeric) {
                    println!("Invalid username. Usernames must be alphanumeric.");
                    continue;
                }
                let mut users_list = users().write().unwrap();
                match users_list.users.contains_key(&username.to_lowercase()) {
                    true => {
                        println!("User already exists.");
                        continue;
                    }
                    false => {
                        match std::fs::create_dir_all(format!("{FILES_DIR}/{}", username.to_lowercase())) {
                            Ok(_) => (),
                            Err(e) => {
                                println!("Failed to create user's data directory: {}", e);
                                continue;
                            }
                        };
                        users_list.users.insert(username.to_lowercase(), UserData::new(password.to_string()));
                        users_list.save();
                        clearscreen::clear().ok();
                        println!("User `{username}` added.");
                    }
                }
            }
            "removeuser"| "remove" | "deleteuser" | "delete" => {
                let username = match split.next() {
                    Some(username) => username,
                    None => {
                        println!("Invalid arguments. The `removeuser` command has the syntax `removeuser <username>`.");
                        continue;
                    }
                };
                let mut users_list = users().write().unwrap();
                match users_list.users.contains_key(&username.to_lowercase()) {
                    true => {
                        let confirm_message = format!("confirm delete {username}");
                        println!("Please type `{confirm_message}` to confirm deletion of the user. WARNING: THIS WILL ALSO DELETE ALL THE DATA THAT IS STORED UNDER THIS USER.");
                        let mut buffer = String::new();
                        std::io::stdin().read_line(&mut buffer)?;
                        let buffer = buffer.trim();
                        if confirm_message != buffer {
                            println!("User deletion cancelled.");
                            continue;
                        }
                        if let Err(e) = std::fs::remove_dir_all(format!("{FILES_DIR}/{}", username.to_lowercase())) {
                            println!("Failed to delete user's data: {}", e);
                            continue
                        };
                        users_list.users.remove(&username.to_lowercase());
                        users_list.save();
                        println!("User `{}` removed.", username);
                    }
                    false => {
                        println!("User `{}` does not exist.", username);
                        continue;
                    }
                }
            }
            "listusers" | "list" => {
                let users_list = users().read().unwrap();
                match users_list.users.len() {
                    0 => println!("There are no users. Add some with `adduser <username> <password>."),
                    _ => {
                        println!("Users:");
                        for (username, user) in users_list.users.iter() {
                            let used = byte_unit::Byte::from_bytes(count_size(&format!("{FILES_DIR}/{username}"))).get_appropriate_unit(false);
                            let limit = byte_unit::Byte::from_bytes(user.max_data as u128).get_appropriate_unit(false);
                            println!("{username} ({used}/{limit})");
                        }
                    }
                }
            }
            "changelimit" | "limit" => {
                let (username, limit) = match (split.next(), split.next().and_then(|l| byte_unit::Byte::from_str(l).ok()).and_then(|l| Some(l.get_bytes() as usize))) {
                    (Some(username), Some(limit)) => (username, limit),
                    _ => {
                        println!("Invalid arguments. The `changelimit` command has the syntax `changelimit <username> <limit>`. (limit can be B, KB, MB, KiB, MiB, GiB, etc)");
                        continue;
                    }
                };
                let mut users_list = users().write().unwrap();
                match users_list.users.get_mut(&username.to_lowercase()) {
                    Some(user) => {
                        user.max_data = limit;
                        users_list.save();
                        println!("User `{}`'s limit changed to {}.", username, limit);
                    }
                    None => {
                        println!("User `{}` does not exist.", username);
                        continue;
                    }
                }
            }
            "help" => {
                let default = byte_unit::Byte::from_bytes(DEFAULT_USER_LIMIT as u128).get_appropriate_unit(false);
                println!("Commands: adduser <username> <password> (Adds a user with the default limit of {default})\nremoveuser <username> (Removes a user)\nlistusers (Lists all users and their limits)\nchangelimit <username> <limit> (Changes a user's limit. Limit can be B, KB, MB, KiB, MiB, GiB, etc. e.g. `changelimit user 1GB`)\nhelp (Shows this message)");
            }
            _ => println!("Invalid command. type `help` for help."),
        }
    }
    //Ok(())
}

async fn async_main() -> Result<(), std::io::Error> {
    
    if !std::path::Path::new("cookie.txt").exists() {
        std::fs::write("cookie.txt", Alphanumeric.sample_string(&mut rand::thread_rng(), 200)).expect("Failed to write cookie.txt");
    }
    let key_string = std::fs::read_to_string("cookie.txt").expect("Should be encoded properly");    
    let secret_key = Key::from(&key_string.as_bytes());


    //println!("Starting server.");
    std::fs::create_dir_all("files").expect("Should be able to create files dir.");
    HttpServer::new(move || {

        let session_middleware = SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
        // disable secure cookie for local testing
            .cookie_secure(false)
            .build();

        App::new()
            .wrap(IdentityMiddleware::default())
            .wrap(session_middleware)
            .app_data(MultipartFormConfig::default().total_limit(5 * 1024 * 1024 * 1024)) // 5gb
            .service(get_file)
            .service(index)
            .service(upload)
            .service(upload_form)
            //.service(player)
            //.service(videojs_css)
            //.service(videojs_js)
            .service(login)
            .service(verify_login)
    })
    .bind(("0.0.0.0", 8080))?
    .workers(1)
    .run()
    .await
    .ok();
    println!("\nServer stopped. Exiting...");
    Ok(())
}

#[derive(Debug, MultipartForm)]
struct UploadForm {
    #[multipart(rename = "file")]
    files: Vec<TempFile>,
}

#[post("/")]
async fn upload_form(
    MultipartForm(form): MultipartForm<UploadForm>,
    user: Identity,
) -> Result<impl Responder, actix_web::Error> {
    //println!("Received upload request.");
    for f in form.files {
        let path = format!("./files/{}", f.file_name.unwrap());
        f.file.persist(path).unwrap();
    }
    todo!();
    Ok(HttpResponse::Ok())
}


#[get("/files/{filename}")]
async fn get_file(path: web::Path<String>, user: Identity) -> actix_web::Result<impl Responder> {
    let id = user.id().expect("Getting user id shouldn't fail");
    let path = path.into_inner();
    let canon = canonicalize(format!("files/{}/{}", id, path));
    let path = match canon {
        Ok(path) => path,
        Err(_) => return Ok(Either::Right(HttpResponse::NotFound().body("Not Found"))),
    };
    let allowed = canonicalize(format!("files/{}", id)).expect("Canonicalizing 'files' shouldn't fail");
    if !path.starts_with(allowed) {
        return Ok(Either::Right(HttpResponse::Forbidden().body("Cannot access this file.")))
    }
    //println!("Received `/files/{path}` request.");
    match NamedFile::open_async(&format!("files/{}", path.display())).await {
        Ok(file) => Ok(Either::Left(file)),
        Err(_) => Ok(Either::Right(HttpResponse::NotFound().body("Not Found"))),
    }
}
/*
#[get("/player/{filename:.*}")]
async fn player(filename: web::Path<String>, _: Identity) -> impl Responder {
    println!("Received `/player/{filename}` request.");
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../web/player.html").replace("INSERT SOURCE HERE", &format!("/{}", filename.into_inner())))
}
 */
#[get("/upload")]
async fn upload(user: Identity) -> impl Responder {
    //println!("Received `/` request.");
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../web/upload.html"))
}

#[get("/login")]
async fn login() -> impl Responder {
    todo!();
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../web/login.html"))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct LoginRequest {
    username: String,
    password: String,
}

#[post("/login")]
async fn verify_login(req: HttpRequest, json: Json<LoginRequest>) -> impl Responder {
    let mut timer = user_timeout().lock().unwrap();
    if let Some(time) = timer.get(&json.username) {
        if time > &std::time::Instant::now() {
            return HttpResponse::TooManyRequests()
                .body("Too many login attempts. Please wait a bit before trying again.");
        }
    }
    timer.insert(json.username.clone(), std::time::Instant::now() + std::time::Duration::from_secs_f32(0.5));
    drop(timer);
    let json = json.into_inner();
    let users_list = users().read().unwrap();
    let random_duration = (&mut rand::thread_rng()).gen::<f32>() / 10.0;
    tokio::time::sleep(std::time::Duration::from_secs_f32(random_duration)).await;
    if let Some(user) = users_list.users.get(&json.username) {
        if user.password == json.password {
            Identity::login(&req.extensions(), json.username.clone()).ok();
            return HttpResponse::Ok()
                .finish();
        }
    }
    HttpResponse::BadRequest()
        .body("Invalid username or password.")
}

#[get("/")]
async fn share(req: HttpRequest) -> impl Responder {
    todo!();
    ""
}

/*
#[get("/videojs.css")]
async fn videojs_css(_: Identity) -> impl Responder {
    println!("Received `/videojs.css` request.");
    HttpResponse::Ok()
        .content_type("text/css; charset=utf-8")
        .body(include_str!("../web/videojs.css"))
}

#[get("/videojs.js")]
async fn videojs_js(_: Identity) -> impl Responder {
    println!("Received `/videojs.js` request.");
    HttpResponse::Ok()
        .content_type("text/javascript; charset=utf-8")
        .body(include_str!("../web/videojs.js"))
}
 */
#[get("/")]
async fn index(user: Identity) -> impl Responder {
    todo!();
    //println!("Received `/contents` request.");
    let body = {
        let mut body = String::from("<h1>Contents</h1><br>");
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
