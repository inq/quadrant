#[macro_use]
extern crate log;

use std::env;

#[derive(Debug)]
enum Error {
    SendRequest(awc::error::SendRequestError),
    Payload(awc::error::PayloadError),
}

async fn main_async() -> Result<(), Error> {
    use awc::Client;
    use tokio::task::spawn_local;

    let mut client = Client::default();

    let mut response = client
        .post("https://i.instagram.com/api/v1/accounts/login")
        .header("User-Agent", "Instagram 144.0.0.17.119 (iPhone8,4; iOS 13_5; en_KR; en-KR; scale=2.00; 640x1136; 217426887) AppleWebKit/420+-web")
        .send()
        .await.map_err(Error::SendRequest)?;

    println!("Response: {:?}", response);

    let body = response.body().await.map_err(Error::Payload)?;
    println!("Downloaded: {:?} bytes", body.len());
    Ok(())
}

fn main() {
    env_logger::init();

    actix_rt::System::new("quadrant")
        .block_on(main_async())
        .unwrap();
}
