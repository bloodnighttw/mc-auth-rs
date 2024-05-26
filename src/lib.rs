
mod auth;
mod utils;

#[cfg(test)]
mod tests {
    use crate::utils::{TimeSensitiveData, TimeSensitiveTrait};
    use crate::auth::{MinecraftAuthorizationFlow, MinecraftAuthStep};

    #[derive(Clone,serde::Serialize,serde::Deserialize,Debug,PartialEq)]
    struct TestStruct {
        duration: std::time::Duration,
    }
    
    impl TimeSensitiveTrait for TestStruct {
        fn get_duration(&self) -> std::time::Duration {
            self.duration
        }
    }

    #[tokio::test]
    async fn time_sensitive_test() {
        let test:TimeSensitiveData<TestStruct> = TimeSensitiveData::new(TestStruct{duration: std::time::Duration::from_secs(1)});
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert!(!test.is_vaild());
    }
    
    #[tokio::test]
    async fn minecraft_auth(){
        let mut auth_step = MinecraftAuthorizationFlow::new("47f3e635-2886-4628-a1c2-fd8a9f4d7a5f");
        auth_step.generate_device_code().await.expect("Failed to generate device code!");
        match &auth_step.status { 
            MinecraftAuthStep::DeviceCode(data) => {
                println!("verification uri:{}",data.data.verification_uri);
                println!("User Code:{:?}",data.data.user_code);
            },
            _ => panic!("Invalid status!")
        }
        auth_step.await_user_accept().await.expect("Failed to exchange device code!");
        let token1 = match &auth_step.status {
            MinecraftAuthStep::MicrosoftAuth(res) => {
                let temp = res.read().await;
                temp.data.access_token.clone()
            }
            _ => panic!("Invalid status!")
        };
        
        auth_step.refresh_microsoft_token().await.expect("Failed to refresh microsoft token!");
        let token2 = match &auth_step.status {
            MinecraftAuthStep::MicrosoftAuth(res) => {
                let temp = res.read().await;
                temp.data.access_token.clone()
            }
            _ => panic!("Invalid status!")
        };
        
        assert_ne!(token1,token2);
        
        auth_step.xbox_live_auth().await.expect("Failed to authenticate with xbox live!");
        auth_step.xbox_security_auth().await.expect("Failed to authenticate with xbox live!");
        auth_step.get_minecraft_token().await.expect("Failed to get minecraft token!");
        auth_step.check_minecraft_profile().await.expect("Failed to get minecraft profile!");
        
        match &auth_step.status { 
            MinecraftAuthStep::MinecraftProfile(data) => {
                println!("Profile:{:?}",data);
            },
            _ => panic!("Invalid status!")
        }
        
    }
    
    #[tokio::test]
    async fn test_json(){
        let test:TimeSensitiveData<TestStruct> = TimeSensitiveData::new(TestStruct{duration: std::time::Duration::from_secs(1)});
        let json = serde_json::to_string(&test).expect("Failed to serialize");
        println!("{}",json);
        let deserialized:TimeSensitiveData<TestStruct> = serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(test,deserialized);
    }
    
}
