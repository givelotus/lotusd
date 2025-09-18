use std::{convert::TryInto, sync::Arc, time::Duration};

use clipboard::{ClipboardContext, ClipboardProvider};
use eframe::{
    egui::{
        self, emath::RectTransform, pos2, Button, Color32, Label, Pos2, Rect, ScrollArea, Shape,
        Stroke, TextEdit,
    },
    epi,
};
use lotus_miner_lib::{settings, ConfigSettings, LogEntry, Miner, Server, ServerRef};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct UserSettings {
    mine_to_address: String,
    intensity: i32,
    bitcoind_url: String,
    bitcoind_user: String,
    bitcoind_password: String,
    rpc_poll_interval: u64,
    gpu_index: i64,
}

pub struct MinerApp {
    user_settings: UserSettings,
    server: ServerRef,
    device_names: Vec<String>,
    rt: Runtime,
    logs: Vec<LogEntry>,
    hashrate_zoom: HashrateZoom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashrateZoom {
    T10m,
    T1h,
    T1d,
    Max,
}

impl MinerApp {
    pub fn load() -> Self {
        let user_settings = match ConfigSettings::load(false) {
            Ok(config_settings) => UserSettings {
                mine_to_address: config_settings.mine_to_address,
                intensity: config_settings.kernel_size.try_into().unwrap(),
                bitcoind_url: config_settings.rpc_url,
                bitcoind_user: config_settings.rpc_user,
                bitcoind_password: config_settings.rpc_password,
                rpc_poll_interval: config_settings.rpc_poll_interval.try_into().unwrap(),
                gpu_index: config_settings.gpu_index,
            },
            Err(err) => {
                eprintln!("Failed to load config, falling back to defaults: {}", err);
                UserSettings {
                    mine_to_address: String::new(),
                    intensity: settings::DEFAULT_KERNEL_SIZE.try_into().unwrap(),
                    bitcoind_url: settings::DEFAULT_URL.to_string(),
                    bitcoind_user: settings::DEFAULT_USER.to_string(),
                    bitcoind_password: settings::DEFAULT_PASSWORD.to_string(),
                    rpc_poll_interval: settings::DEFAULT_RPC_POLL_INTERVAL.try_into().unwrap(),
                    gpu_index: settings::DEFAULT_GPU_INDEX,
                }
            }
        };
        let config = ConfigSettings {
            rpc_url: user_settings.bitcoind_url.clone(),
            rpc_user: user_settings.bitcoind_user.clone(),
            rpc_password: user_settings.bitcoind_password.clone(),
            rpc_poll_interval: user_settings.rpc_poll_interval.try_into().unwrap(),
            mine_to_address: user_settings.mine_to_address.clone(),
            kernel_size: user_settings.intensity.into(),
            gpu_index: user_settings.gpu_index,
        };
        MinerApp {
            user_settings,
            server: Arc::new(Server::from_config(config, Duration::from_millis(300))),
            device_names: Miner::list_device_names(),
            rt: tokio::runtime::Runtime::new().unwrap(),
            logs: Vec::new(),
            hashrate_zoom: HashrateZoom::T10m,
        }
    }
}

impl epi::App for MinerApp {
    fn name(&self) -> &str {
        "Lotus GPU Miner"
    }

    fn save(&mut self, storage: &mut dyn epi::Storage) {
        epi::set_value(storage, epi::APP_KEY, &self.user_settings);
    }

    fn setup(
        &mut self,
        _ctx: &egui::CtxRef, 
        _frame: &mut epi::Frame<'_>,
        storage: Option<&dyn epi::Storage>,
    ) {
        match storage {
            Some(storage) => {
                if let Some(user_settings) = epi::get_value(storage, epi::APP_KEY) {
                    self.user_settings = user_settings;
                }
            }
            None => println!("No storage"),
        }
        std::thread::spawn({
            let server = Arc::clone(&self.server);
            move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async move { server.run().await.unwrap() })
            }
        });
        self._apply_settings();
    }

    fn update(&mut self, ctx: &egui::CtxRef, _frame: &mut epi::Frame<'_>) {
        ctx.request_repaint();
        self.logs
            .append(&mut self.server.log().get_logs_and_clear());

        egui::SidePanel::left("side_panel").default_width(300.0).show(ctx, |ui| {
            ui.heading("Settings (\"Apply & Mine\" to update)");

            egui::Grid::new("panel_grid")
                .striped(true)
                .spacing([40.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Miner address: ");
                    ui.text_edit_singleline(&mut self.user_settings.mine_to_address);
                    ui.end_row();

                    ui.label("Intensity: ");
                    ui.add(egui::Slider::new(
                        &mut self.user_settings.intensity,
                        8i32..=27,
                    ));
                    ui.end_row();

                    ui.label("RPC URL: ");
                    ui.text_edit_singleline(&mut self.user_settings.bitcoind_url);
                    ui.end_row();

                    ui.label("RPC User: ");
                    ui.text_edit_singleline(&mut self.user_settings.bitcoind_user);
                    ui.end_row();

                    ui.label("RPC Password: ");
                    ui.add(
                        TextEdit::singleline(&mut self.user_settings.bitcoind_password)
                            .password(true),
                    );
                    ui.end_row();

                    ui.label("RPC Poll Interval: ");
                    ui.add(egui::Slider::new(
                        &mut self.user_settings.rpc_poll_interval,
                        1..=10,
                    ));
                    ui.end_row();

                    ui.label("GPU: ");
                    egui::ComboBox::from_id_source("gpu")
                        .selected_text(
                            self.device_names
                                .get(self.user_settings.gpu_index as usize)
                                .map(String::as_str)
                                .unwrap_or(""),
                        )
                        .show_ui(ui, |ui| {
                            for (device_idx, device_name) in self.device_names.iter().enumerate() {
                                ui.selectable_value(
                                    &mut self.user_settings.gpu_index,
                                    device_idx as i64,
                                    device_name,
                                );
                            }
                        });
                    ui.end_row();

                    ui.label("");
                    let btn_apply = Button::new("Apply & Mine")
                        .text_color(Color32::BLACK)
                        .fill(Color32::LIGHT_GRAY);
                    if ui.add(btn_apply).clicked() {
                        self._apply_settings();
                    }
                    ui.end_row();
                });

            let hashrate_text = match self.server.log().hashrates().last() {
                Some(hashrate) => hashrate.to_string(),
                None => "Hashrate: calculating...".to_string(),
            };
            ui.add(Label::new(hashrate_text).heading());
            ui.horizontal(|ui| {
                ui.radio_value(&mut self.hashrate_zoom, HashrateZoom::T10m, "10m");
                ui.radio_value(&mut self.hashrate_zoom, HashrateZoom::T1h, "1h");
                ui.radio_value(&mut self.hashrate_zoom, HashrateZoom::T1d, "1d");
                ui.radio_value(&mut self.hashrate_zoom, HashrateZoom::Max, "Max");
            });

            let (_id, rect) = ui.allocate_space(ui.available_size());

            let mut shapes = vec![];

            let hashrate_duration = match self.hashrate_zoom {
                HashrateZoom::T10m => chrono::Duration::minutes(10),
                HashrateZoom::T1h => chrono::Duration::hours(1),
                HashrateZoom::T1d => chrono::Duration::days(1),
                HashrateZoom::Max => chrono::Duration::max_value(),
            };
            let now = chrono::Local::now();
            let mut points: Vec<(chrono::Duration, f64)> = Vec::new();
            let mut max_age = chrono::Duration::zero();
            let mut max_hashrate = 0.0;
            for hashrate in self.server.log().hashrates().iter() {
                let age = now.signed_duration_since(hashrate.timestamp);
                if age <= hashrate_duration {
                    points.push((age, hashrate.hashrate));
                    if age > max_age {
                        max_age = age;
                    }
                    if hashrate.hashrate > max_hashrate {
                        max_hashrate = hashrate.hashrate;
                    }
                }
            }
            let to_screen = RectTransform::from_to(
                Rect::from_x_y_ranges(
                    0.0..=max_age.num_milliseconds() as f32,
                    max_hashrate as f32..=0.0,
                ),
                rect,
            );
            let points: Vec<Pos2> = points
                .iter()
                .map(|&(age, hashrate)| {
                    let time = max_age - age;
                    to_screen * pos2(time.num_milliseconds() as f32, hashrate as f32)
                })
                .collect();
            let thickness = 2.0;
            shapes.push(Shape::line(
                points,
                Stroke::new(thickness, Color32::from_additive_luminance(196)),
            ));

            ui.painter().extend(shapes);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Logs");
            if ui.button("Copy").clicked() {
                let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                let mut logs = String::new();
                for log in self.logs.iter() {
                    logs.push_str(&log.to_string());
                    logs.push('\n');
                }
                if let Err(err) = ctx.set_contents(logs) {
                    self.server
                        .log()
                        .error(format!("Error setting clipboard: {}", err));
                }
            }
            ScrollArea::auto_sized().show(ui, |ui| {
                for log in self.logs.iter().rev() {
                    ui.label(log.to_string());
                }
            });
        });
    }
}

impl MinerApp {
    fn _apply_settings(&mut self) {
        let server = Arc::clone(&self.server);
        self.server.log().info("Applying settings");
        let user_settings = self.user_settings.clone();
        self.rt.spawn(async move {
            let mut node_settings = server.node_settings().await;
            node_settings.bitcoind_url = user_settings.bitcoind_url;
            node_settings.bitcoind_user = user_settings.bitcoind_user;
            node_settings.bitcoind_password = user_settings.bitcoind_password;
            node_settings.rpc_poll_interval = user_settings.rpc_poll_interval;
            node_settings.miner_addr = user_settings.mine_to_address;
            let mut miner = server.miner();
            miner.set_intensity(user_settings.intensity);
            let result = miner.update_gpu_index(user_settings.gpu_index);
            if let Err(err) = result {
                server.log().error(err);
            }
        });
    }
}
