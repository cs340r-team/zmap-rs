#![allow(unused, non_camel_case_types, non_snake_case, non_upper_case_globals, special_module_name)]

mod crypto;
mod lib;
mod net;
mod recv;

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .format_target(false)
        .init();

    // Spawn a thread to run the packet capture,
    // more complex logic will be added around this
    let recv_thread = std::thread::spawn(|| {
        recv::run();
    });
    recv_thread.join().unwrap();
}
