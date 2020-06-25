use serde::{Serialize, Deserialize};

pub enum Error {
    SendRequest(awc::error::SendRequestError),
    JsonPayload(awc::error::JsonPayloadError),
    ToStr(http::header::ToStrError),
}

#[derive(Serialize, Deserialize)]
struct Payload {
    signed_body: String,
}

mod res {
    use serde::{Serialize, Deserialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Response {
        experiments: Vec<Experiment>,
        status: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Experiment {
        name: String,
        group: String,
        additional_params: Vec<()>,
        params: Vec<Param>,
        logging_id: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Param {
        name: String,
        value: String,
    }
}

pub async fn request(config: &crate::Config) -> Result<(), Error> {
    use awc::Client;

    let payload = Payload {
        signed_body: format!(r#"SIGNATURE.{{"id":"{}","server_config_retrieval":"1"}}"#, config.device_id),
    };

    let client = Client::default();
    let mut response = client.post("https://i.instagram.com/api/v1/qe/sync/")
        .header("X-IG-App-ID", "124024574287414")
        .header("X-Bloks-Version-Id", "555f61dd0ded5ddf4201c89e12bb453bf605f9bc9d321a69f6e0f11ed9308664")
        .header("Accept-Language", "en-US;q=1.0")
        .header("X-IG-Connection-Type", "WiFi")
        .header("X-IG-Bandwidth-Speed-KBPS", "0.000")
        .header("X-IG-App-Startup-Country", "KR")
        .header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        .header("X-IG-ABR-Connection-Speed-KBPS", "0")
        .header("X-IG-Capabilities", "36r/Fwc=")
        .header("User-Agent", "Instagram 144.0.0.17.119 (iPhone8,4; iOS 13_5; en_KR; en-KR; scale=2.00; 640x1136; 217426887) AppleWebKit/420+")
        .header("X-IG-Connection-Speed", "-1kbps")
        .header("X-IG-Device-Locale", "en-KR")
        .header("X-IG-Mapped-Locale", "en_US")
        .header("X-IG-Device-ID", config.device_id.clone())
        .header("X-IG-App-Locale", "en")
        .header("X-MID", "XvGHWgAAAAFtt2sfnl2MxRhFaNmk")
        .header("Cookie", "csrftoken=0V97QP4qC8ZMytxb2br2OLBynGLIbyy1; rur=VLL; mid=XvGHWgAAAAFtt2sfnl2MxRhFaNmk")
        .header("X-Tigon-Is-Retry", "False")
        .header("Accept-Encoding", "gzip, deflate")
        .header("X-FB-HTTP-Engine", "Liger")
        .header("Connection", "close")
        .send_form(&payload).await
        .map_err(Error::SendRequest)?;

    let enc_pub_key = response.headers().get("ig-set-password-encryption-pub-key").unwrap();
    println!("{}", enc_pub_key.to_str().map_err(Error::ToStr)?);
    let _body: res::Response = response.json().await.map_err(Error::JsonPayload)?;

    Ok(())
}
