extern crate argon2;

use argon2::{Variant, Version, ThreadMode};
use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::{self, general_purpose}, alphabet, DecodeError};
use config::{Config, ConfigError, File};
use toml;
use serde::{Deserialize, Serialize};
use std::{env, result, fs};

#[derive(Debug, Deserialize)]
pub struct ConfigService {
    aes_256_key: String,
    salt: String
}

impl ConfigService {
    pub fn get_aes_256_key(&self)-> &str {
        &self.aes_256_key
    }

    pub fn get_salt(&self) ->&str {
        &self.salt
    }

    pub fn new() -> Result<Self, ConfigError> {
       let run_mode: String = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());
        
        let settings: Config = Config::builder()
        .add_source(config::File::with_name("Settings"))
        .add_source(
            File::with_name(&format!("Settings.{}", run_mode))
            .required(false),
        )
        .build()
        .map_err(ConfigError::into)?;
    
        settings.try_deserialize()
    }

    pub fn verify_key(&self, hashed_key: &str) -> Result<bool> {
        const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

        let aes_256_key: &str = self.get_aes_256_key();
        println!("stored aes_256_key: {}", aes_256_key);
        let salt: &str = self.get_salt();
        println!("stored salt: {}", salt);

        let decoded_key = CUSTOM_ENGINE.decode(&aes_256_key).unwrap();
        println!("stored decoded_key: {:?}", &decoded_key);

        // let bytes_aes_256_key: &[u8] = aes_256_key.as_bytes();
        // let config: argon2::Config = argon2::Config::default();
        // let decoded_salt = CUSTOM_ENGINE.decode(salt).unwrap();

        // let hash: String = argon2::hash_encoded(bytes_aes_256_key, &decoded_salt, &config).unwrap();
        // if hash != hashed_key {
        //     return Err(anyhow!("Hashed key does not match expected key"));
        // }
        // let matches: bool = argon2::verify_encoded(&hashed_key, bytes_aes_256_key).unwrap();

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::{Result, Ok};
    use argon2::{Config};
    use rand::{thread_rng, Rng};
    use rand::distributions::Alphanumeric;
    use std::{collections::BTreeMap, fs};

    use super::*;

    // #[derive(Debug, Default, Serialize)]
    // struct Settings<'a> {
    //     settings: BTreeMap<&'a str, Setting<'a>>,
    // }

    #[derive(Debug, Default, Serialize)]
    struct Setting<'a> {
        #[serde(rename = "aes_256_key")]
        aes_256_key: &'a str,

        #[serde(rename = "salt")]
        salt: &'a str,
    }

    fn base64_encode(input: &str) -> Result<String> {
        const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
        Ok(CUSTOM_ENGINE.encode(&input))
    }

    fn base64_decode(input: &str) -> Result<Vec<u8>> {
        const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
        let decoded = CUSTOM_ENGINE.decode(&input).unwrap();
        Ok(decoded)
    }

    fn generate_random_key() -> Result<String> {
        const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

        let mut key: [u8; 32] = [0u8; 32];
        thread_rng()
            .fill(&mut key[..]);

        println!("orignal key: {:?}", key);

        let encoded_key: String = CUSTOM_ENGINE.encode(&key);

        Ok(encoded_key)
    }

    fn remove_file() -> Result<()> {
        if let std::result::Result::Ok(metadata) = fs::metadata("Settings.test.toml") {
            fs::remove_file("Settings.test.toml").expect("Could remove the file!");
            Ok(())
        } else {
            println!("File does not exist, nothing to remove.");
            Ok(())
        }
    }

    fn generate_toml(encoded_key: &str, salt: &str) {
        let mut file:Setting = Setting::default();
        
        file.aes_256_key = encoded_key;
        file.salt = salt;

        let toml_string = toml::to_string(&file).expect("Could not encode TOML value");
        println!("{}", toml_string);
        fs::write("Settings.test.toml", toml_string).expect("Could not write to file!");
    }

    // #[test]
    // fn test_new() {
    //     env::set_var("RUN_MODE", "test");
    //     let encoded_key: String = generate_random_key().unwrap();
    //     let salt: &str = "randomsalt";
    //     let salt_encoded: String = base64_encode(&salt).unwrap();
       
    //     //generate_toml(&encoded_key, &salt_encoded);
    //     //let settings: ConfigService = ConfigService::new().unwrap();
    //     remove_file();
    // }

    // #[test]
    // fn test_get_aes_256_key() {
    //     env::set_var("RUN_MODE", "test");
    //     let encoded_key: String = generate_random_key().unwrap();
    //     println!("encoded_key: {}", encoded_key);
    //     let salt: &str = "randomsalt";
    //     let salt_encoded: String = base64_encode(&salt).unwrap();
       
    //     generate_toml(&encoded_key, &salt_encoded);

    //     let settings: ConfigService = ConfigService::new().unwrap();
    //     println!("settings encoded_key: {}", settings.get_aes_256_key());

    //     assert_eq!(settings.get_aes_256_key().len(), encoded_key.len());
    //     assert_eq!(settings.get_aes_256_key(), encoded_key);
    //     remove_file();
    // }

    // fn test_get_salt() {
    //     env::set_var("RUN_MODE", "test");
    //     let encoded_key: String = generate_random_key().unwrap();
    //     let salt: &str = "randomsalt";
    //     let salt_encoded: String = base64_encode(&salt).unwrap();
       
    //     generate_toml(&encoded_key, &salt_encoded);

    //     let settings: ConfigService = ConfigService::new().unwrap();
    //     assert_eq!(settings.get_salt().len(), salt_encoded.len());
    //     assert_eq!(settings.get_salt(), salt_encoded);
    //     remove_file();
    // }

    // #[test]
    // fn test_verify_key_with_wrong_hashed_key() {
    //     env::set_var("RUN_MODE", "test");

    //     let wrong_hashed_key = "$argon2i$v=19$m=4096,t=3,p=1$cldaV2xWaVdmbg$I5O1IjynzqxxRZanKOYfBm3KpX4Z2g2wL93PKw0HDZ5";
    //     let settings: ConfigService = ConfigService::new().unwrap();
    //     let error = settings.verify_key(wrong_hashed_key).unwrap_err();
        
    //     assert_eq!(format!("{}", error), "Hashed key does not match expected key");
    // }

    #[test]
    fn test_verify_key() {
        env::set_var("RUN_MODE", "test");
        let encoded_key: String = generate_random_key().unwrap();
        let salt: &str = "randomsalt";
        let salt_encoded: String = base64_encode(&salt).unwrap();
       
        generate_toml(&encoded_key, &salt_encoded);

        let decoded_key = base64_decode(&encoded_key).unwrap();

        let config = argon2::Config::default();
        let hashed_key = argon2::hash_encoded(&decoded_key, &salt.as_bytes(), &config).unwrap();

        let settings:ConfigService = ConfigService::new().unwrap();
        settings.verify_key(&hashed_key).unwrap();
        //remove_file();
    }
}