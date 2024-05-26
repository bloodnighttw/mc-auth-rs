use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use reqwest::{Client, Error, Response};
use reqwest::header::{CONTENT_TYPE};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value};
use thiserror::Error;
use crate::Data::{TimeSensitiveData, TimeSensitiveTrait};

const DEVICECODE_URL:&str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
const TOKEN_URL:&str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const MINECRAFT_LOGIN_WITH_XBOX: &str = "https://api.minecraftservices.com/authentication/login_with_xbox";
const XBOX_USER_AUTHENTICATE: &str = "https://user.auth.xboxlive.com/user/authenticate";
const XBOX_XSTS_AUTHORIZE: &str = "https://xsts.auth.xboxlive.com/xsts/authorize";
const MINECRAFT_PROFILE: &str = "https://api.minecraftservices.com/minecraft/profile";
const SCOPE: &str = "XboxLive.signin offline_access";
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

pub enum MinecraftAuthStep{
    /// Initialize the Minecraft Authorization Flow.
    Init(),
    /// Generate a device code for the user to authorize.
    /// This is the first step in the Minecraft Authorization Flow.
    /// The user must open the URL in a browser and enter the code.
    /// The user code is valid for a limited time.
    /// The user must authorize the app within this time.
    /// If the user does not authorize the app within this time, the user code will expire.
    DeviceCode(TimeSensitiveData<DeviceCodeResponse>),
    /// Wait for the user to authorize the app.
    MicrosoftAuth(Arc<TimeSensitiveData<MicrosoftAuthResponse>>),

    /// Exchange the device code for an access token.
    XboxLiveAuth(String),
    /// Exchange the Xbox Live access token for an Xbox Security Token.
    XboxSecurityAuth(String,String),
    /// Exchange the Xbox Security Token for a Minecraft access token.
    /// Get the user's Minecraft profile to check player have minecraft or not.
    MinecraftAuth(MinecraftAuthResponse),
    MinecraftProfile(MinecraftProfile),
}

#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum MinecraftAuthError{

    #[error("Your Minecraft Auth Flow call wrong step! Please check your code.")]
    InvalidState,
    #[error("Failed to get device code. details:{0}")]
    GetDeviceCodeError(String),
    #[error("Failed to exchange device code. please try again. details:AuthorizationPending")]
    AuthorizationPending,
    #[error("Failed to exchange device code. details: AuthorizationDeclined")]
    AuthorizationDeclined,
    #[error("Failed to exchange device code. details: BadVerificationCode")]
    BadVerificationCode,
    #[error("Failed to exchange device code. details: ExpiredToken")]
    ExpiredToken,
    #[error("Failed to fetching Xbox Data. details:{0}")]
    XboxAuthError(String),
    #[error("The account doesn't have an Xbox account. Once they sign up for one (or login through minecraft.net to create one) then they can proceed with the login")]
    XboxAccountNotExist,
    #[error("The account doesn't have a Minecraft account. Once they sign up for one (or login through minecraft.net to create one) then they can proceed with the login")]
    XboxAccountCountryBan,
    #[error("The account needs adult verification on Xbox page")]
    XboxAccountNeedAdultVerification,
    #[error("The account is a child (under 18) and cannot proceed unless the account is added to a Family by an adult.")]
    AddToFamily,
    #[error("Profile Not Found. details:{0}")]
    ProfileNotFound(String),
    #[error("Unknown Error. details:{0}")]
    UnknownError(String),
}

fn to_duration<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    Ok(match Value::deserialize(deserializer)? {
        Value::Number(num) =>{
            let v = num.as_u64().ok_or(de::Error::custom("Invalid number"))?;
            Duration::from_secs(v)
        } ,
        _ => return Err(de::Error::custom("wrong type"))
    })
}

fn to_u64<S>(x: &Duration, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
{
    s.serialize_u64(x.as_secs())
}

#[derive(Debug, serde::Deserialize ,serde::Serialize,Clone)]
pub struct DeviceCodeResponse{
    pub user_code: String,
    pub device_code: String,
    pub verification_uri: String,
    #[serde(deserialize_with = "to_duration",serialize_with = "to_u64")]
    pub expires_in: Duration,
    pub interval: u64,
}

impl TimeSensitiveTrait for DeviceCodeResponse {
    fn get_duration(&self) -> Duration {
        self.expires_in
    }
}

#[derive(Debug, serde::Deserialize ,serde::Serialize)]
pub struct MicrosoftAuthResponse{
    pub token_type: String,
    pub scope: String,
    #[serde(deserialize_with = "to_duration",serialize_with = "to_u64")]
    pub expires_in: Duration,
    pub ext_expires_in: u64,
    pub access_token: String,
    pub refresh_token: String,
}

impl TimeSensitiveTrait for MicrosoftAuthResponse {
    fn get_duration(&self) -> Duration {
        self.expires_in
    }
}


pub struct MinecraftAuthorizationFlow {
    client: Client,
    client_id: String,
    pub status: MinecraftAuthStep
}

#[derive(Serialize, Deserialize)]
pub struct MinecraftAuthResponse{
    username: String,
    access_token: String,
    #[serde(deserialize_with = "to_duration",serialize_with = "to_u64")]
    expires_in: Duration,
    token_type: String,
}

#[derive(Debug,Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MinecraftSkin {
    pub id: String,
    pub state: String,
    pub url: String,
    pub texture_key: String,
    pub variant: String,
}

#[derive(Debug,Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MinecraftCaps {
    pub id: String,
    pub state: String,
    pub url: String,
    pub alias: String,
}


/// Represents the information of user's Minecraft profile
#[derive(Debug,Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MinecraftProfile {
    pub id: String,
    pub name: String,
    pub skins: Vec<MinecraftSkin>,
    pub capes: Vec<MinecraftCaps>,
}

impl MinecraftAuthorizationFlow {

    pub fn new(client_id:&str) -> Self {
        Self {
            client: Client::new(),
            client_id: client_id.to_string(),
            status: MinecraftAuthStep::Init()
        }
    }

    pub fn from(client_id:&str,step:MinecraftAuthStep) -> Self {
        Self {
            client: Client::new(),
            client_id: client_id.to_string(),
            status: step
        }
    }

    pub fn reset(&mut self){
        self.status = MinecraftAuthStep::Init();
    }

    ///
    ///
    pub async fn generate_device_code(&mut self) -> Result<(), MinecraftAuthError>{
        let params:HashMap<String,String> = HashMap::from([
            (String::from("client_id"),self.client_id.clone()),
            (String::from("scope"),String::from(SCOPE)),
        ]);
        let response = self.client.post(DEVICECODE_URL)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await;
        
        let data:DeviceCodeResponse = match response{
            Ok(response) => {
                if response.status() == 200{
                    response.json().await.expect("this should be success!")
                }else{
                    return Err(MinecraftAuthError::GetDeviceCodeError(format!("Failed to get device code. status code:{}",response.status())))
                }
            },
            Err(e) => return Err(MinecraftAuthError::GetDeviceCodeError(e.to_string()))
        };
        
        self.status = MinecraftAuthStep::DeviceCode(TimeSensitiveData::new(data));
        Ok(())
    }
    
    pub async fn exchange_device_code(&mut self) -> Result<(), MinecraftAuthError>{
        let data = match &self.status{
            MinecraftAuthStep::DeviceCode(data) => data,
            _ => return Err(MinecraftAuthError::InvalidState)
        };
        
        let params:HashMap<String,String> = HashMap::from([
            (String::from("client_id"),self.client_id.clone()),
            (String::from("grant_type"),String::from(GRANT_TYPE)),
            (String::from("device_code"),data.data.device_code.clone()),
        ]);
        
        let request = self.client.post(TOKEN_URL)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&params);
        
        let response = request.try_clone().expect("should can").send().await;
        let response:MicrosoftAuthResponse = match response{
            Ok(response) => {
                if response.status() == 200{
                    response.json().await.expect("this should be success!")
                }else {
                    return match response.json::<Value>().await.expect("this should be success!")
                        .get("error").expect("this should be success!")
                        .as_str().expect("this should be success!"){
                        "authorization_pending" => Err(MinecraftAuthError::AuthorizationPending),
                        "authorization_declined" => Err(MinecraftAuthError::AuthorizationDeclined),
                        "bad_verification_code" => Err(MinecraftAuthError::BadVerificationCode),
                        "expired_token" => Err(MinecraftAuthError::ExpiredToken),
                        _ => Err(MinecraftAuthError::UnknownError("Unknown Error".to_string()))
                    }
                }
            },
            Err(e) => return Err(MinecraftAuthError::UnknownError(e.to_string()))
        };

        self.status = MinecraftAuthStep::MicrosoftAuth(Arc::new(TimeSensitiveData::new(response)));

        Ok(())
    }

    pub async fn await_user_accept(&mut self) -> Result<(), MinecraftAuthError>{
        loop{
            let result = self.exchange_device_code().await;
            match result{
                Ok(_) => break,
                Err(e) => {
                    match e{
                        MinecraftAuthError::AuthorizationPending => {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        },
                        _ => return Err(e)
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn xbox_live_auth(&mut self) -> Result<(), MinecraftAuthError>{
        let data = match &self.status{
            MinecraftAuthStep::MicrosoftAuth(data) => data,
            _ => return Err(MinecraftAuthError::InvalidState)
        };

        let xbox_authenticate_json = json!({
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": &format!("d={}", data.data.access_token)
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        });
        let response = self
            .client
            .post(XBOX_USER_AUTHENTICATE)
            .json(&xbox_authenticate_json)
            .send()
            .await;

        let res = match response{
            Ok(response) => {
                if response.status() == 200{
                    response
                }else{
                    return Err(MinecraftAuthError::XboxAuthError(format!("Failed to get Xbox Data. status code:{}",response.status())))
                }
            },
            Err(e) => return Err(MinecraftAuthError::UnknownError(e.to_string()))
        };

        let token = res.json::<Value>().await.expect("this should be success!")
            .get("Token").expect("this should be success!")
            .as_str().expect("this should be success!").to_string();

        self.status = MinecraftAuthStep::XboxLiveAuth(token);

        Ok(())
    }

    pub async fn xbox_security_auth(&mut self) -> Result<(), MinecraftAuthError>{
        let token = match &self.status{
            MinecraftAuthStep::XboxLiveAuth(token) => token,
            _ => return Err(MinecraftAuthError::InvalidState)
        };

        let xbox_authenticate_json = json!({
            "Properties": {
                "SandboxId": "RETAIL",
                "UserTokens": [token],
            },
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT"
        });
        let response = self
            .client
            .post(XBOX_XSTS_AUTHORIZE)
            .json(&xbox_authenticate_json)
            .send()
            .await;

        let res = match response{
            Ok(response) => {
                if response.status() == 200{
                    response
                }else{
                    let value = response.json::<Value>().await.expect("this should be success!");
                    return match value["XErr"].as_u64().expect("should be x") {
                        2148916233 => Err(MinecraftAuthError::XboxAccountNotExist),
                        2148916235 => Err(MinecraftAuthError::XboxAccountCountryBan),
                        2148916236|2148916237 => Err(MinecraftAuthError::XboxAccountNeedAdultVerification),
                        2148916238 => Err(MinecraftAuthError::AddToFamily),
                        _ => Err(MinecraftAuthError::XboxAuthError("Unknown Error".to_string()))
                    }
                }
            },
            Err(e) => return Err(MinecraftAuthError::UnknownError(e.to_string()))
        };

        let value = res.json::<Value>().await.or(Err(MinecraftAuthError::UnknownError("Failed to parse response".to_string())))?;
        let token = value["Token"].as_str().expect("this should be success!").to_string();
        let user_hash = value["DisplayClaims"]["xui"][0]["uhs"].as_str().expect("this should be success!").to_string();

        self.status = MinecraftAuthStep::XboxSecurityAuth(token,user_hash);

        Ok(())
    }

    pub async fn get_minecraft_token(&mut self) -> Result<(),MinecraftAuthError>{
        let (token,uhs) = match &self.status{
            MinecraftAuthStep::XboxSecurityAuth(token,user_hash) => (token,user_hash),
            _ => return Err(MinecraftAuthError::InvalidState)
        };

        let response = self.client.post(MINECRAFT_LOGIN_WITH_XBOX)
            .header("Content-Type", "application/json")
            .json(&json!({
                "identityToken": format!("XBL3.0 x={};{}",uhs,token)
            }))
            .send()
            .await;
        
        let res:MinecraftAuthResponse = match response{
            Ok(response) => {
                if response.status() == 200{
                    response.json().await.expect("this should be success!")
                }else{
                    return Err(MinecraftAuthError::XboxAuthError(format!("Failed to get Xbox Data. status code:{}",response.status())))
                }
            },
            Err(e) => return Err(MinecraftAuthError::UnknownError(e.to_string()))
        };
        
        self.status = MinecraftAuthStep::MinecraftAuth(res);
        
        Ok(())
    }
    
    pub async fn check_minecraft_profile(&mut self) -> Result<(),MinecraftAuthError>{
        
        let data = match &self.status{
            MinecraftAuthStep::MinecraftAuth(data) => data,
            _ => return Err(MinecraftAuthError::InvalidState)
        };
        
        let response = self.client.get(MINECRAFT_PROFILE)
            .bearer_auth(data.access_token.clone())
            .send()
            .await;
        
        let profile_data = match response {
            Ok(response) => {
                if response.status() == 200{
                    response.json::<MinecraftProfile>().await.expect("this should be success!")
                }else{
                    return Err(MinecraftAuthError::ProfileNotFound(response.text().await.expect("this should be success!")))
                }
            },
            Err(e) => {
                return Err(MinecraftAuthError::UnknownError(e.to_string()))
            }
        };
        
        self.status = MinecraftAuthStep::MinecraftProfile(profile_data);
        
        Ok(())
    }
    
}