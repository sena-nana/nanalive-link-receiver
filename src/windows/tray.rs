use anyhow::{Context, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::time::Duration;
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIconBuilder};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, TranslateMessage,
};

#[derive(Clone, Debug)]
pub enum TrayState {
    Listening(String),
    Connected(String),
    Decoding,
    SpoutActive(String),
    Error(String),
}

impl TrayState {
    fn text(&self) -> String {
        match self {
            Self::Listening(address) => format!("Listening: {address}"),
            Self::Connected(address) => format!("Connected: {address}"),
            Self::Decoding => "Hardware decoding active".to_owned(),
            Self::SpoutActive(name) => format!("Spout active: {name}"),
            Self::Error(error) => format!("Error: {error}"),
        }
    }
}

#[derive(Clone)]
pub struct TrayController {
    state: Sender<TrayState>,
    reconnect: Arc<AtomicBool>,
}

impl TrayController {
    pub fn start(shutdown: Arc<AtomicBool>) -> Result<Self> {
        let (state, receiver) = mpsc::channel();
        let reconnect = Arc::new(AtomicBool::new(false));
        let reconnect_thread = Arc::clone(&reconnect);
        std::thread::Builder::new()
            .name("nanalive-link-tray".to_owned())
            .spawn(move || {
                let menu = Menu::new();
                let status = MenuItem::new("Starting NanaLive Link receiver", false, None);
                let reconnect_item = MenuItem::new("Reconnect", true, None);
                let exit_item = MenuItem::new("Exit", true, None);
                if menu
                    .append_items(&[&status, &reconnect_item, &exit_item])
                    .is_err()
                {
                    shutdown.store(true, Ordering::Release);
                    return;
                }
                let icon = receiver_icon();
                let Ok(tray) = TrayIconBuilder::new()
                    .with_menu(Box::new(menu))
                    .with_tooltip("NanaLive Link receiver")
                    .with_icon(icon)
                    .build()
                else {
                    shutdown.store(true, Ordering::Release);
                    return;
                };
                while !shutdown.load(Ordering::Acquire) {
                    let mut message = MSG::default();
                    while unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE).as_bool() } {
                        unsafe {
                            let _ = TranslateMessage(&message);
                            DispatchMessageW(&message);
                        }
                    }
                    while let Ok(state) = receiver.try_recv() {
                        let text = state.text();
                        status.set_text(&text);
                        let _ = tray.set_tooltip(Some(format!("NanaLive Link - {text}")));
                    }
                    while let Ok(event) = MenuEvent::receiver().try_recv() {
                        if event.id == *reconnect_item.id() {
                            reconnect_thread.store(true, Ordering::Release);
                        } else if event.id == *exit_item.id() {
                            shutdown.store(true, Ordering::Release);
                        }
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
            .context("start Windows tray thread")?;
        Ok(Self { state, reconnect })
    }

    pub fn set_state(&self, state: TrayState) {
        let _ = self.state.send(state);
    }

    pub fn take_reconnect(&self) -> bool {
        self.reconnect.swap(false, Ordering::AcqRel)
    }
}

fn receiver_icon() -> Icon {
    let mut rgba = Vec::with_capacity(16 * 16 * 4);
    for y in 0..16 {
        for x in 0..16 {
            let inside = (2..14).contains(&x) && (2..14).contains(&y);
            let accent = inside && (x == 4 || x == 11 || y == 4 || y == 11);
            rgba.extend_from_slice(if accent {
                &[255, 255, 255, 255]
            } else if inside {
                &[105, 75, 220, 255]
            } else {
                &[0, 0, 0, 0]
            });
        }
    }
    Icon::from_rgba(rgba, 16, 16).expect("valid built-in tray icon")
}
