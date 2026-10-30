// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

mod backup;
mod musig;
mod penlock_ui;
mod scan;
mod single;
mod theme;
mod wallet_ui;

use slint_keyos_platform::app_ui2;

app_ui2!("my-app");

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    theme::init(&ui);
    penlock_ui::init(&cx, &ui);
    wallet_ui::init(&ui);

    ui.global::<Callbacks>().on_dismiss_toast({
        let ui = ui.as_weak();
        move || ui.upgrade().expect("window outlives callbacks").global::<AppState>().set_toast("".into())
    });

    ui.run().expect("UI running");
}
