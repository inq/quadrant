#[macro_use]
extern crate log;

mod api;
mod config;
use config::Config;
use serde_json::json;
use std::env;

#[derive(Debug)]
enum Error {
    SendRequest(awc::error::SendRequestError),
    Payload(awc::error::PayloadError),
    YamlParse(serde_yaml::Error),
    IoError(std::io::Error),
    Qe(api::qe::Error),
    Rsa(rsa::errors::Error),

}

fn encrypt(password: &str, pub_key: rsa::pem::Pem, key_id: u8) -> Result<String, Error> {
    use aes::block_cipher::NewBlockCipher;
    use std::convert::TryFrom;
    use rand::Rng;
    use rsa::PublicKey;

    let mut rng = rand::thread_rng();
    let key: [u8; 32] = rng.gen();
    let iv: [u8; 12] = rng.gen();

    let pub_key = rsa::RSAPublicKey::try_from(pub_key).map_err(Error::Rsa)?;
    let padding = rsa::PaddingScheme::new_pkcs1v15_encrypt();
    let enc_data = pub_key.encrypt(&mut rng, padding, &password.as_bytes());
    println!("{:?}", enc_data);

    let enc = aes::Aes256::new(&aes::block_cipher::generic_array::GenericArray::clone_from_slice(&key));
    let mut encrypted = vec![];
    encrypted.push(1u8);
    encrypted.push(key_id);
    println!("{:?}", encrypted);
    //let password_buffer = password

    // info!("{:?}", enc_data);
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

    Ok(String::from("11"))
}

async fn main_async() -> Result<(), Error> {
    use tokio::task::spawn_local;

    let reader = std::fs::File::open("config.yaml").map_err(Error::IoError)?;
    let config: Config = serde_yaml::from_reader(reader).map_err(Error::YamlParse)?;

    //let request = client.post("https://i.instagram.com/api/v1/accounts/login");

    let qe_res = api::qe::request(&config).await.map_err(Error::Qe)?;
    let username = "gofiri";
    let password = "1234";
    let encrypted = encrypt(password, qe_res.pub_key, qe_res.key_id)?;
    /*
    let payload = json!({
        username: username,
        password: password,
        enc_password: format!("#PWD_INSTAGRAM:4:{}:{}", time, encrypted),
    });
    */

    Ok(())
}

fn main() {
    env_logger::init();

    actix_rt::System::new("quadrant")
        .block_on(main_async())
        .unwrap();
}
