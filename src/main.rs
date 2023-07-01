use std::collections::HashMap;
use std::fs::{canonicalize, read_dir};
use std::io::Write;
use std::path::{Component, PathBuf};
use std::time::Instant;

use actix_files::NamedFile;
use actix_web::web::Json;
use actix_web::{cookie::Key, get, post, web, App, Either, HttpServer, Responder};
use actix_web::{HttpMessage, HttpRequest, HttpResponse};

use actix_multipart::form::{tempfile::TempFile, MultipartForm, MultipartFormConfig};

use actix_identity::{Identity, IdentityMiddleware};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use rand::distributions::{Alphanumeric, DistString};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, OnceLock, RwLock};

const DEFAULT_USER_LIMIT: u64 = 1000 * 1000 * 1000 * 10; // 10gb
const CONFIG_PATH: &'static str = "config/";
const FILES_DIR: &'static str = "files";
const IP: &'static str = "127.0.0.1";
const PORT: u16 = 8080;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct UserData {
    max_data: u64,
    password: String,
    current_data: u64,
}

impl UserData {
    fn new(p: String) -> Self {
        Self {
            max_data: DEFAULT_USER_LIMIT,
            current_data: 0,
            password: p,
        }
    }
}

fn user_timeout() -> &'static Mutex<HashMap<String, Instant>> {
    static USER_TIMEOUT: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    USER_TIMEOUT.get_or_init(|| Mutex::new(HashMap::new()))
}

fn save_file_share(h: &HashMap<String, PathBuf>) {
    std::fs::write(
        format!("{CONFIG_PATH}file_share.json"),
        serde_json::to_string(h).unwrap(),
    ).ok();
}

fn file_share_directory() -> &'static RwLock<HashMap<String, PathBuf>> {
    static USER_TIMEOUT: OnceLock<RwLock<HashMap<String, PathBuf>>> = OnceLock::new();
    USER_TIMEOUT.get_or_init(|| RwLock::new(HashMap::new()))
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Users {
    users: HashMap<String, UserData>,
}

impl Users {
    fn save(&self) {
        std::fs::write(
            format!("{CONFIG_PATH}users.json"),
            serde_json::to_string(self).unwrap(),
        )
        .expect("Failed to write to config file.");
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

fn get_proper_icon(s: &PathBuf) -> &'static str {
    use infer::MatcherType::*;
    let kind = infer::get_from_path(s).ok().and_then(|i| i.and_then(|i| Some(i.matcher_type()))).unwrap_or(Custom);
    match kind {
        Archive => "/images/archive.png",
        Audio => "/images/audio.png",
        Doc => "/images/doc.png",
        Image => "/images/image.png",
        Video => "/images/video.png",
        _ => "/images/other.png"
    }
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
                        match std::fs::create_dir_all(format!(
                            "{FILES_DIR}/{}",
                            username.to_lowercase()
                        )) {
                            Ok(_) => (),
                            Err(e) => {
                                println!("Failed to create user's data directory: {}", e);
                                continue;
                            }
                        };
                        users_list
                            .users
                            .insert(username.to_lowercase(), UserData::new(password.to_string()));
                        users_list.save();
                        clearscreen::clear().ok();
                        println!("User `{username}` added.");
                    }
                }
            }
            "removeuser" | "remove" | "deleteuser" | "delete" => {
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
                        if let Err(e) = std::fs::remove_dir_all(format!(
                            "{FILES_DIR}/{}",
                            username.to_lowercase()
                        )) {
                            println!("Failed to delete user's data: {}", e);
                            continue;
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
                    0 => println!(
                        "There are no users. Add some with `adduser <username> <password>."
                    ),
                    _ => {
                        println!("Users:");
                        for (username, user) in users_list.users.iter() {
                            let used = byte_unit::Byte::from_bytes(count_size(&format!(
                                "{FILES_DIR}/{username}"
                            )))
                            .get_appropriate_unit(false);
                            let limit = byte_unit::Byte::from_bytes(user.max_data as u128)
                                .get_appropriate_unit(false);
                            println!("{username} ({used}/{limit})");
                        }
                    }
                }
            }
            "changelimit" | "limit" => {
                let (username, limit) = match (
                    split.next(),
                    split
                        .next()
                        .and_then(|l| byte_unit::Byte::from_str(l).ok())
                        .and_then(|l| Some(l.get_bytes() as u64)),
                ) {
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
                let default = byte_unit::Byte::from_bytes(DEFAULT_USER_LIMIT as u128)
                    .get_appropriate_unit(false);
                println!("Commands: adduser <username> <password> (Adds a user with the default limit of {default})\nremoveuser <username> (Removes a user)\nlistusers (Lists all users and their limits)\nchangelimit <username> <limit> (Changes a user's limit. Limit can be B, KB, MB, KiB, MiB, GiB, etc. e.g. `changelimit user 1GB`)\nhelp (Shows this message)");
            }
            _ => println!("Invalid command. type `help` for help."),
        }
    }
    //Ok(())
}

async fn async_main() -> Result<(), std::io::Error> {
    if !std::path::Path::new("cookie.txt").exists() {
        std::fs::write(
            "cookie.txt",
            Alphanumeric.sample_string(&mut rand::thread_rng(), 200),
        )
        .expect("Failed to write cookie.txt");
    }
    let key_string = std::fs::read_to_string("cookie.txt").expect("Should be encoded properly");
    let secret_key = Key::from(&key_string.as_bytes());

    //println!("Starting server.");
    std::fs::create_dir_all("files").expect("Should be able to create files dir.");
    HttpServer::new(move || {
        let session_middleware =
            SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
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
            .service(share)
            .service(create_share_link)
            .service(logout)
            .service(get_image)
    })
    .bind((IP, PORT))?
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
    let id = user.id().expect("Getting user id should not fail");
    for f in form.files {
        let mut user_list = users().write().unwrap();
        let user_data = user_list
            .users
            .get_mut(&id)
            .expect("If logged in, user should exist");
        let file_length = f
            .file
            .as_file()
            .metadata()
            .expect("Shouldn't error on getting metadata")
            .len();
        if user_data.max_data < count_size(&id) as u64 + file_length {
            // limit exceeded.
            return Ok(HttpResponse::PayloadTooLarge().finish());
        }
        drop(user_list);
        let path = format!("./files/{}/{}", &id, f.file_name.unwrap());
        f.file.persist(path).unwrap();
    }
    Ok(HttpResponse::Ok().finish())
}

#[get("/images/{image}")]
async fn get_image(image: web::Path<String>) -> impl Responder {
    let image = image.into_inner();
    let mut http_response = HttpResponse::Ok();
    let http_response = http_response.content_type("image/png");
    let http_response = match image.trim() {
        "archive.png" => http_response.body(&include_bytes!("../web/images/archive.png")[..]),
        "audio.png" => http_response.body(&include_bytes!("../web/images/audio.png")[..]),
        "document.png" => http_response.body(&include_bytes!("../web/images/document.png")[..]),
        "folder.png" => http_response.body(&include_bytes!("../web/images/folder.png")[..]),
        "image.png" => http_response.body(&include_bytes!("../web/images/image.png")[..]),
        "other.png" => http_response.body(&include_bytes!("../web/images/other.png")[..]),
        "video.png" => http_response.body(&include_bytes!("../web/images/video.png")[..]),

        _ => HttpResponse::Unauthorized().body("Not Found"),
    };
    http_response
}

#[post("/makesharelink/{filename:.*}")]
async fn create_share_link(user: Identity, path: web::Path<String>) -> impl Responder {
    let id = user.id().expect("Getting user id shouldn't fail");
    let path = path.into_inner();
    let canon = canonicalize(format!("files/{}/{}", id, path));
    let path = match canon {
        Ok(path) => path,
        Err(_) => return HttpResponse::NotFound().body("Not Found"),
    };
    let allowed =
        canonicalize(format!("files/{}", id)).expect("Canonicalizing 'files' shouldn't fail");
    if !path.starts_with(allowed) {
        return HttpResponse::NotFound().body("Not Found");
    }
    let mut share_file_hashmap = file_share_directory().write().unwrap();
    let file_id = loop {
        let file_id = Alphanumeric.sample_string(&mut rand::thread_rng(), 50);
        if share_file_hashmap.contains_key(&file_id) {
            continue;
        };
        break file_id;
    };
    share_file_hashmap.insert(file_id.clone(), path);
    save_file_share(&share_file_hashmap);
    HttpResponse::Ok().body(file_id)
}

#[get("/files/{filename:.*}")]
async fn get_file(original_path: web::Path<String>, user: Identity) -> actix_web::Result<impl Responder> {
    let id = user.id().expect("Getting user id shouldn't fail");
    let original_path = original_path.into_inner();
    let canon = canonicalize(format!("files/{}/{}", id, original_path));
    let path = match canon {
        Ok(path) => path,
        // file doesn't exist on filesystem.
        Err(_) => return Ok(Either::Right(HttpResponse::NotFound().body("Not Found"))),
    };
    let allowed =
        canonicalize(format!("files/{}", id)).expect("Canonicalizing 'files' shouldn't fail");
    if !path.starts_with(allowed) {
        // if the path isn't in the user's directory, return 404 because this means they're trying to access a file they shouldn't be able to.
        // eg: path traversal attack
        return Ok(Either::Right(HttpResponse::NotFound().body("Not Found")));
    }
    if path.is_file() {
        // if the path is a file, return the file.
        match NamedFile::open_async(&path.display().to_string()).await {
            Ok(file) => Ok(Either::Left(file)),
            Err(_) => Ok(Either::Right(HttpResponse::NotFound().body("Not Found"))),
        }
    } else {
        let return_string = include_str!("../web/explorer.html");
        let mut long_path = String::from("/files");
        let v = PathBuf::from(&original_path)
            .components()
            .map(|c| {
                if let Component::Normal(component) = c {
                    long_path.push_str(format!("/{}", component.to_string_lossy()).as_str());
                    format! {
                        "<a href=\"{}\">{}</a>",
                        long_path,
                        component.to_string_lossy()
                    }
                } else {
                    "".into()
                }
            })
            .filter(|s| s != "")
            .collect::<Vec<String>>()
            .join(" / ");
        let entries = {
            let id_clone = id.clone();
            let (dirs, files) = match tokio::task::spawn_blocking(move || {
                let mut dirs = vec![];
                let mut files = vec![];
                for (loop_index, entry) in read_dir(path).expect("Reading this directory should not fail").enumerate() {
                    let entry = if let Ok(entry) = entry {
                        entry
                    } else {
                        continue;
                    };
                    let icon = if entry.file_type().expect("Shouldn't fail on opening this").is_dir() {
                        "/images/folder.png"
                    } else {
                        get_proper_icon(&entry.path())
                    };
                    let entry_text = format! {
                        r#"<div class="inner-wrapper"><img class="img" src="{}"><div class="directory-item" data-url="{}" data-index="{loop_index}">{}</div></div>"#,
                        icon,
                        entry.path().display().to_string().replacen(&format!("/{}", id_clone), "", 1),
                        entry.file_name().to_string_lossy(),
                    };
                    if entry.file_type().expect("Shouldn't fail on opening this").is_dir() {
                        dirs.push((entry_text, entry.file_name()))
                    } else {
                        files.push((entry_text, entry.file_name()))
                    }
                    
                }
                dirs.sort_by_key(|d| d.1.clone());
                files.sort_by_key(|f| f.1.clone());
                let dirs: Vec<String> = dirs.iter().map(|d| d.0.clone()).collect();
                let files: Vec<String> = files.iter().map(|f| f.0.clone()).collect();
                (dirs, files)
            }).await {
                Ok(entries) => entries,
                Err(_) => return Ok(Either::Right(HttpResponse::InternalServerError().finish())),
            };
            format!("{}{}", dirs.join(""), files.join(""))
        };
        let return_string = return_string
            .replace("USERNAME_HERE", &id)
            .replace("CURRENT_PATH_HERE", &v)
            .replace("DIRECTORY_HERE", &entries);
        Ok(Either::Right(
            HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(return_string),
        ))
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
async fn upload(_: Identity) -> impl Responder {
    //println!("Received `/` request.");
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../web/upload.html"))
}

#[get("/login")]
async fn login() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../web/login.html"))
}

#[get("/logout")]
async fn logout(user: Option<Identity>) -> impl Responder {
    if let Some(user) = user {
        user.logout();
    }
    HttpResponse::TemporaryRedirect()
        .append_header(("Location", "/"))
        .finish()
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
    timer.insert(
        json.username.clone(),
        std::time::Instant::now() + std::time::Duration::from_secs_f32(0.5),
    );
    drop(timer);
    let json = json.into_inner();
    let users_list = users().read().unwrap();
    let random_duration = (&mut rand::thread_rng()).gen::<f32>() / 10.0;
    tokio::time::sleep(std::time::Duration::from_secs_f32(random_duration)).await;
    if let Some(user) = users_list.users.get(&json.username) {
        if user.password == json.password {
            Identity::login(&req.extensions(), json.username.clone()).ok();
            return HttpResponse::Ok().finish();
        }
    }
    HttpResponse::BadRequest().body("Invalid username or password.")
}

#[get("/shared/<id>")]
async fn share(id: web::Path<String>) -> actix_web::Result<impl Responder> {
    let share_list = file_share_directory().read().unwrap();
    let id = id.into_inner();
    if let Some(f) = share_list.get(&id) {
        match NamedFile::open_async(&f).await {
            Ok(file) => Ok(Either::Left(file)),
            Err(_) => Ok(Either::Right(HttpResponse::NotFound().body("Not Found"))),
        }
    } else {
        Ok(Either::Right(
            HttpResponse::NotFound().body("Could not find the share id"),
        ))
    }
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
async fn index(user: Option<Identity>) -> impl Responder {
    let user = match user {
        Some(user) => user,
        None => return HttpResponse::TemporaryRedirect().append_header(("Location", "/login")).finish(),
    };
    let id = user.id().expect("Getting user id shouldn't fail");
    let path = format!("files/{}/", id);
    let return_string = include_str!("../web/explorer.html");
    let entries = {
        let id_clone = id.clone();
        let (dirs, files) = match tokio::task::spawn_blocking(move || {
            let mut dirs = vec![];
            let mut files = vec![];
            for (loop_index, entry) in read_dir(path).expect("Reading this directory should not fail").enumerate() {
                let entry = if let Ok(entry) = entry {
                    entry
                } else {
                    continue;
                };
                let icon = if entry.file_type().expect("Shouldn't fail on opening this").is_dir() {
                    "/images/folder.png"
                } else {
                    get_proper_icon(&entry.path())
                };
                let entry_text = format! {
                    r#"<div class="inner-wrapper"><img class="img" src="{}"><div class="directory-item" data-url="{}" data-index="{loop_index}">{}</div></div>"#,
                    icon,
                    entry.path().display().to_string().replacen(&format!("/{}", id_clone), "", 1),
                    entry.file_name().to_string_lossy(),
                };
                if entry.file_type().expect("Shouldn't fail on opening this").is_dir() {
                    dirs.push((entry_text, entry.file_name()))
                } else {
                    files.push((entry_text, entry.file_name()))
                }
                
            }
            dirs.sort_by_key(|d| d.1.clone());
            files.sort_by_key(|f| f.1.clone());
            let dirs: Vec<String> = dirs.iter().map(|d| d.0.clone()).collect();
            let files: Vec<String> = files.iter().map(|f| f.0.clone()).collect();
            (dirs, files)
        }).await {
            Ok(entries) => entries,
            Err(_) => return HttpResponse::InternalServerError().finish(),
        };
        format!("{}{}", dirs.join(""), files.join(""))
    };
    let return_string = return_string
        .replace("USERNAME_HERE", &id)
        .replace("CURRENT_PATH_HERE", "")
        .replace("DIRECTORY_HERE", &entries);
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(return_string)
}
