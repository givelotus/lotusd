mod app;

fn main() {
    let app = app::MinerApp::load();
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(Box::new(app), native_options);
}
