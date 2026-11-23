#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// The console's single command; every operation is a local simulation in aegismesh-core.
#[tauri::command]
async fn aegismesh(op: String, request: serde_json::Value) -> Result<serde_json::Value, String> {
    aegismesh_core::console::handle(&op, &request)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![aegismesh])
        .run(tauri::generate_context!())
        .expect("failed to start the AegisMesh console");
}
