extern crate argon2;
extern crate keyring;

use argon2::{Variant, Version, ThreadMode};
use anyhow::{anyhow, Result};
use base64::{Engine as _, engine::{self, general_purpose}, alphabet, DecodeError};
use config::{Config, ConfigError, File, Environment};
use crypto::salsa20;
use dotenv::dotenv;
use keyring::Entry;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use toml;
use serde::{Deserialize, Serialize};
use std::{env, result, fs};
use sqlx::{PgPool, Postgres};

#[derive(Debug, Deserialize)]
pub struct ConfigService {
    pub host: String,
    pub port: i32,
    pub database_host: String,
    pub database_name: String,
    pub database_user: String,
    pub database_password: String,
    pub database_port: String,
    pub database_url: String,
    app_name: String
}

impl ConfigService {

    pub fn get_app_name(&self) -> &str {
        return &self.app_name;
    }

    // get AES_256 key from Keyring
    pub fn get_aes_256_key(&self)-> Result<String> {
        println!("Getting AES key from keyring app_name {}", &self.app_name);
        let aes_key: String = keyring::Entry::new(&self.app_name, "aes_256_key")
            .get_password()
            .map_err(|e| anyhow!("Error getting AES key from keyring: {}", e))?;
        Ok(aes_key)
    }

    // pub fn get_salt(&self) -> Result<String> {
    //     let salt: String = keyring::Entry::new(&self.app_name, "salt")
    //         .get_password()
    //         .map_err(|e| anyhow!("Error getting salt from keyring: {}", e))?;
    //     Ok(salt)
    // }

    pub fn from_env() -> Result<ConfigService, ConfigError> {
        let run_mode: String = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());

        // Loading environment variables
        dotenv().ok();

        let mut c: Config = Config::new();

        c.merge(Environment::default())?;
    
        c.try_into()
    }

    /// Creates a connection pool to the PostgreSQL database specified in the configuration.
    // #[instrument(skip(self))]
    pub async fn db_pool(&self) -> Result<PgPool> {
        // info!("Creating database connection pool.");
        let database_url = format!(
            "{}{}:{}@{}:{}/{}",
            &self.database_url,
            &self.database_user,
            &self.database_password,
            &self.database_host,
            &self.database_port,
            &self.database_name
        );
        return Ok(PgPool::connect(&database_url)
            .await
            .expect("creating database connection pool"));
    }

    pub fn create_key(&self) -> Result<(String, String)> {
        const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

        let mut key: [u8; 32] = [0u8; 32];
        let mut salt: [u8; 14] = [0u8; 14];
        thread_rng().fill(&mut key[..]);
        thread_rng().fill(&mut salt[..]);

        let encoded_key: String = CUSTOM_ENGINE.encode(&key);
        println!("encoded_key: {}", encoded_key);
        println!("&self.app_name: {:?}", &self.app_name);
        let entry_key: Entry = keyring::Entry::new(&self.app_name, "aes_256_key");
        println!("entry_key: {:?}", entry_key);

        let encoded_salt: String = CUSTOM_ENGINE.encode(&salt);
        println!("encoded_salt: {}", encoded_salt);
        let entry_salt: Entry = keyring::Entry::new(&self.app_name, "salt");
        Ok((encoded_key, encoded_salt))
    }

    // pub fn verify_key(&self, hashed_key: &str) -> Result<bool> {
    //     const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

    //     let aes_256_key: String = self.get_aes_256_key().unwrap();
    //     let salt: String = self.get_salt().unwrap();

    //     let decoded_key = CUSTOM_ENGINE.decode(&aes_256_key).unwrap();
        
    //     let config: argon2::Config = argon2::Config::default();
    //     let decoded_salt = CUSTOM_ENGINE.decode(salt).unwrap();

    //     let hash: String = argon2::hash_encoded(&decoded_key, &decoded_salt, &config).unwrap();
    //     if hash != hashed_key {
    //         return Err(anyhow!("Hashed key does not match expected key"));
    //     }
    //     let matches: bool = argon2::verify_encoded(&hashed_key, &decoded_key).unwrap();

    //     Ok(true)
    // }
}

#[cfg(test)]
mod tests {
    use anyhow::{Result, Ok};
    use argon2::{Config};
    use rand::{thread_rng, Rng};
    use rand::distributions::Alphanumeric;
    use std::{collections::BTreeMap, fs};

    use super::*;

    #[derive(Debug, Default, Serialize)]
    struct Setting<'a> {
        #[serde(rename = "aes_256_key")]
        aes_256_key: &'a str,

        #[serde(rename = "salt")]
        salt: &'a str,
    }

    // fn base64_encode(input: &str) -> Result<String> {
    //     const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
    //     Ok(CUSTOM_ENGINE.encode(&input))
    // }

    // fn base64_decode(input: &str) -> Result<Vec<u8>> {
    //     const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
    //     let decoded = CUSTOM_ENGINE.decode(&input).unwrap();
    //     Ok(decoded)
    // }

    // fn generate_random_key() -> Result<String> {
    //     const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

    //     let mut key: [u8; 32] = [0u8; 32];
    //     thread_rng()
    //         .fill(&mut key[..]);

    //     let encoded_key: String = CUSTOM_ENGINE.encode(&key);

    //     Ok(encoded_key)
    // }

    // fn remove_file() -> Result<()> {
    //     if let std::result::Result::Ok(metadata) = fs::metadata("Settings.test.toml") {
    //         fs::remove_file("Settings.test.toml").expect("Could remove the file!");
    //         Ok(())
    //     } else {
    //         println!("File does not exist, nothing to remove.");
    //         Ok(())
    //     }
    // }

    // fn generate_(encoded_key: &str, salt: &str) {
    //     let mut file:Setting = Setting::default();
        
    //     file.aes_256_key = encoded_key;
    //     file.salt = salt;

    //     let toml_string = toml::to_string(&file).expect("Could not encode TOML value");
    //     fs::write(".env.test", toml_string).expect("Could not write to file!");
    // }

    #[test]
    fn test_new() {
        env::set_var("RUN_MODE", "test");
        let settings = ConfigService::new().unwrap();
        println!("settings: {:?}", settings);
        let keys: (String, String) = settings.create_key().unwrap();
        println!("keys: {:?}", keys);

        assert_eq!(settings.get_aes_256_key().unwrap().len(), 43);
        assert_eq!(settings.get_salt().unwrap().len(), 14);
    }

    // #[test]
    // fn test_get_aes_256_key() {
    //     env::set_var("RUN_MODE", "test");
    //     let settings:ConfigService = ConfigService::new().unwrap();
    //     let encoded_key: &str = settings.get_aes_256_key();

    //     assert_eq!(settings.get_aes_256_key().len(), encoded_key.len());
    //     assert_eq!(settings.get_aes_256_key(), encoded_key);
    // }

    // fn test_get_salt() {
    //     env::set_var("RUN_MODE", "test");
    //     env::set_var("RUN_MODE", "test");
    //     let settings:ConfigService = ConfigService::new().unwrap();
    //     let encoded_salt: &str = settings.get_salt();

    //     assert_eq!(settings.get_salt().len(), encoded_salt.len());
    //     assert_eq!(settings.get_salt(), encoded_salt);
    // }

    // #[test]
    // fn test_verify_key_with_wrong_hashed_key() {
    //     env::set_var("RUN_MODE", "test");

    //     let wrong_hashed_key = "$argon2i$v=19$m=4096,t=3 p=1$cldaV2xWaVdmbg$I5O1IjynzqxxRZanKOYfBm3KpX4Z2g2wL93PKw0HDZ5";
    //     let settings: ConfigService = ConfigService::new().unwrap();
    //     let error = settings.verify_key(wrong_hashed_key).unwrap_err();
        
    //     assert_eq!(format!("{}", error), "Hashed key does not match expected key");
    // }

    // #[test]
    // fn test_verify_key() {
    //     env::set_var("RUN_MODE", "test");

    //     let settings:ConfigService = ConfigService::new().unwrap();
    //     let encoded_key: &str = settings.get_aes_256_key();
    //     let encoded_salt: &str = settings.get_salt();

    //     let decoded_key: Vec<u8> = base64_decode(&encoded_key).unwrap();
    //     let decoded_salt : Vec<u8>= base64_decode(&encoded_salt).unwrap();

    //     let config = argon2::Config::default();
    //     let hashed_key = argon2::hash_encoded(&decoded_key, &decoded_salt, &config).unwrap();

    //     let settings:ConfigService = ConfigService::new().unwrap();
    //     assert!(settings.verify_key(&hashed_key).unwrap());
    // }
}