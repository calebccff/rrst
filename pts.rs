
pub mod config;

#[no_mangle]
pub extern "C" fn pts_client_init(config: *const config::RRSTConfig) -> i32 {
    println!("init config: {:?}", config);
    0
}
