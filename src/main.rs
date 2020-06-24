#[macro_use]
extern crate log;

mod config;
use config::Config;
use std::env;
use serde_json::json;

#[derive(Debug)]
enum Error {
    SendRequest(awc::error::SendRequestError),
    Payload(awc::error::PayloadError),
    YamlParse(serde_yaml::Error),
    IoError(std::io::Error),
}

fn encrypt(password: &str) -> String {
    let mut rng = rand::thread_rng();
    /*
    let key = rng.gen::<u8, 32>();
    let iv = rng.gen::<u8, 12>();
    */
    String::from("D")
    /*
    let rsa_encrypted = rsa::
    const rsaEncrypted = crypto.publicEncrypt({
      key: Buffer.from(this.client.state.passwordEncryptionPubKey, 'base64').toString(),
      // @ts-ignore
      padding: crypto.constants.RSA_PKCS1_PADDING,
    }, randKey);
    const cipher = crypto.createCipheriv('aes-256-gcm', randKey, iv);
    const time = Math.floor(Date.now() / 1000).toString();
    cipher.setAAD(Buffer.from(time));
    const aesEncrypted = Buffer.concat([cipher.update(password, 'utf8'), cipher.final()]);
    const sizeBuffer = Buffer.alloc(2, 0);
    sizeBuffer.writeInt16LE(rsaEncrypted.byteLength, 0);
    const authTag = cipher.getAuthTag();
    return {
      time,
      encrypted: Buffer.concat([
        Buffer.from([1, this.client.state.passwordEncryptionKeyId]),
        iv,
        sizeBuffer,
        rsaEncrypted, authTag, aesEncrypted])
        .toString('base64'),
    };*/

}

async fn main_async() -> Result<(), Error> {
    use awc::Client;
    use tokio::task::spawn_local;

    let reader = std::fs::File::open("config.yaml").map_err(Error::IoError)?;
    let config: Config = serde_yaml::from_reader(reader).map_err(Error::YamlParse)?;

    let client = Client::default();

    let request = client.post("https://i.instagram.com/api/v1/accounts/login");

    let mut response = config.fillup_headers(request)
        .send()
        .await
        .map_err(Error::SendRequest)?;

    // let a: i32 = response.headers().get("")
    println!("Response: {:?}", response);

    /*
    let username = "gofiri";
    let password = "1234";
    let payload = json!({
        username: username,
        password: password,
        enc_password: format!("#PWD_INSTAGRAM:4:{}:{}", time, encrypted),
    });
    */

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
