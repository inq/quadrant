use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub device_id: String,
    app_startup_country: String,
    capabilities: String,
    device_locale: String,
    ds_user_id: i32,
    user_agent: String,
    mid: String,
}

impl Config {
    pub fn fillup_headers(&self, mut request: awc::ClientRequest) -> awc::ClientRequest {
        request
            .header("X-IG-Device-ID", self.device_id.clone())
            .header("X-IG-App-Startup-Country", self.app_startup_country.clone())
            .header("X-IG-Capabilities", self.capabilities.clone())
            .header("X-IG-Device-Locale", self.device_locale.clone())
            .header("X-IG-ABR-Connection-Speed-KBPS", "3")
            .header("IG-U-Ds-User-ID", self.ds_user_id.to_string())
            .header("Accept-Language", "en-US;q=1.0")
            .header("User-Agent", self.user_agent.clone())
            .header(
                "Content-Type",
                "application/x-www-form-urlencoded; charset=UTF-8",
            )
            .header("X-IG-App-Locale", "en")
            .header("X-IG-Extended-CDN-Thumbnail-Sizes", "249,373,412")
            .header("X-IG-Bandwidth-Speed-KBPS", "4.110")
            .header("X-IG-Mapped-Locale", "en_US")
            .header("X-MID", self.mid.clone())
            .header("IG-U-Shbid", "14798")
            .header("IG-U-Shbts", "1592053459.6494713")
            .header(
                "X-Bloks-Version-Id",
                "555f61dd0ded5ddf4201c89e12bb453bf605f9bc9d321a69f6e0f11ed9308664",
            )
            .header("X-IG-Connection-Speed", "137kbps")
            .header("X-IG-App-ID", "124024574287414")
            .header("X-IG-Connection-Type", "WiFi")
            .header("X-Tigon-Is-Retry", "False")
            .header("Accept-Encoding", "gzip, deflate")
            .header("X-FB-HTTP-Engine", "Liger")
            .header("Connection", "close")
    }
}
