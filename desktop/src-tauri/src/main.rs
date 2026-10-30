// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Desktop shell for the unified system monitor.
//!
//! On startup it:
//!   1. picks a free loopback port and generates a one-shot token,
//!   2. spawns the bundled `portscanner-backend` sidecar bound to that port in
//!      `desktop` mode, so it trusts the token for loopback requests only,
//!   3. hands the URL and token to the web UI through the `local_backend` command,
//!      which is why the desktop app never asks you to log in to your own machine,
//!   4. shuts the sidecar down again when the window closes.
//!
//! It also exposes `http_request`, which performs the UI's HTTP calls from Rust. The
//! webview runs in a secure context and would block plain-HTTP requests to a remote
//! server on the LAN as mixed content, so routing them here is what makes the
//! "add a server" feature work in the packaged app.

use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{Manager, RunEvent, State};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;
use tokio::sync::Notify;

/// What the UI needs in order to talk to the backend running on this machine.
#[derive(Clone, Serialize)]
struct LocalBackend {
    url: String,
    token: String,
}

struct Backend {
    info: LocalBackend,
    ready: Arc<AtomicBool>,
    failed: Arc<Mutex<Option<String>>>,
    notify: Arc<Notify>,
    child: Mutex<Option<CommandChild>>,
}

/// A free port, chosen by the OS. Bound and immediately released, which leaves a
/// small race window; the backend binding it again a moment later is good enough in
/// practice and far simpler than passing a socket across processes.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .unwrap_or(8765)
}

fn generate_token() -> String {
    format!(
        "{:016x}{:016x}",
        rand::random::<u64>(),
        rand::random::<u64>()
    )
}

/// Where the local backend is, waiting for it to finish starting up if necessary.
#[tauri::command]
async fn local_backend(state: State<'_, Backend>) -> Result<LocalBackend, String> {
    if !state.ready.load(Ordering::SeqCst) {
        let notify = state.notify.clone();
        let ready = state.ready.clone();

        let wait = async {
            while !ready.load(Ordering::SeqCst) {
                notify.notified().await;
            }
        };

        if tokio::time::timeout(Duration::from_secs(45), wait)
            .await
            .is_err()
        {
            return Err("The local monitoring service did not start in time.".into());
        }
    }

    if let Some(err) = state.failed.lock().unwrap().clone() {
        return Err(err);
    }

    Ok(state.info.clone())
}

#[derive(Deserialize)]
struct HttpRequest {
    url: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: Option<String>,
}

#[derive(Serialize)]
struct HttpResponse {
    status: u16,
    body: String,
}

/// Perform one HTTP request on the UI's behalf.
#[tauri::command]
async fn http_request(req: HttpRequest) -> Result<HttpResponse, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|e| e.to_string())?;

    let method = req
        .method
        .as_deref()
        .unwrap_or("GET")
        .parse::<reqwest::Method>()
        .map_err(|_| "Unsupported HTTP method".to_string())?;

    let mut builder = client.request(method, &req.url);
    for (name, value) in &req.headers {
        builder = builder.header(name, value);
    }
    if let Some(body) = req.body {
        builder = builder.body(body);
    }

    let res = builder.send().await.map_err(|e| {
        if e.is_timeout() {
            "The server took too long to answer.".to_string()
        } else if e.is_connect() {
            "Could not connect to that address.".to_string()
        } else {
            e.to_string()
        }
    })?;

    let status = res.status().as_u16();
    let body = res.text().await.unwrap_or_default();
    Ok(HttpResponse { status, body })
}

fn main() {
    let port = free_port();
    let token = generate_token();

    let state = Backend {
        info: LocalBackend {
            url: format!("http://127.0.0.1:{port}"),
            token: token.clone(),
        },
        ready: Arc::new(AtomicBool::new(false)),
        failed: Arc::new(Mutex::new(None)),
        notify: Arc::new(Notify::new()),
        child: Mutex::new(None),
    };

    let ready = state.ready.clone();
    let failed = state.failed.clone();
    let notify = state.notify.clone();

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![local_backend, http_request])
        .setup(move |app| {
            let sidecar = app
                .shell()
                .sidecar("portscanner-backend")?
                .args([
                    "--mode",
                    "desktop",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    &port.to_string(),
                    "--local-token",
                    &token,
                ]);

            let (mut rx, child) = sidecar.spawn()?;
            app.state::<Backend>()
                .child
                .lock()
                .unwrap()
                .replace(child);

            // Watch the sidecar's output: it prints a JSON line when it is listening,
            // which is the handshake `local_backend` is waiting on.
            tauri::async_runtime::spawn(async move {
                let mark_ready = |notify: &Notify, ready: &AtomicBool| {
                    ready.store(true, Ordering::SeqCst);
                    notify.notify_waiters();
                };

                while let Some(event) = rx.recv().await {
                    match event {
                        CommandEvent::Stdout(line) => {
                            let text = String::from_utf8_lossy(&line);
                            println!("[backend] {}", text.trim_end());
                            if text.contains("\"event\": \"ready\"") {
                                mark_ready(&notify, &ready);
                            }
                        }
                        CommandEvent::Stderr(line) => {
                            let text = String::from_utf8_lossy(&line);
                            eprintln!("[backend] {}", text.trim_end());
                            // Fallback handshake in case stdout is swallowed.
                            if text.contains("Application startup complete") {
                                mark_ready(&notify, &ready);
                            }
                        }
                        CommandEvent::Terminated(payload) => {
                            if !ready.load(Ordering::SeqCst) {
                                *failed.lock().unwrap() = Some(format!(
                                    "The local monitoring service exited before it was ready (code {:?}).",
                                    payload.code
                                ));
                                mark_ready(&notify, &ready);
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to start the monitor window");

    app.run(|handle, event| {
        // Don't leave the backend running after the window is gone.
        if let RunEvent::Exit = event {
            if let Some(child) = handle.state::<Backend>().child.lock().unwrap().take() {
                let _ = child.kill();
            }
        }
    });
}
