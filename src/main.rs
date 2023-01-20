// use serde::Serialize; // 1.0.91
// use std::{ fs};
// use toml; // 0.5.1

// #[derive(Debug, Default, Serialize)]
// struct Settings<'a> {
//     settings: BTreeMap<&'a str, Setting<'a>>,
// }

// #[derive(Debug, Default, Serialize)]
// struct Setting<'a> {
//     #[serde(rename = "aes_256_key")]
//     aes_256_key: &'a str,

//     #[serde(rename = "salt")]
//     salt: &'a str,
// }

// fn main() {
//     let mut file = Setting::default();
//     file.aes_256_key = "192.168.4.1";

//     file.salt = "4476";

//     let toml_string = toml::to_string(&file).expect("Could not encode TOML value");
//     println!("{}", toml_string);
//     fs::write("Settings.development.toml", toml_string).expect("Could not write to file!");
// }
// // use argon2::{Config};
// // use rand::{thread_rng, Rng};
// // use base64::{Engine as _, engine::{self, general_purpose}, alphabet};
// // use crypto_service::config::ConfigService;

// // use std::fs;
// // use toml::{map::Map, Value}; // 0.5.1

// // fn main() {
   
// //     const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

// //     // let settings = ConfigService::new().unwrap();
// //     // println!("settings: {:?}", settings);
// //     // println!("settings: {:?}", settings.get_aes_256_key().len());
// //     // println!("settings: {:?}", settings.get_salt().len());

// //     // let wrong_encoded_salt: &str = "cddaV2xWaVdmbg";
// //     // let result = CUSTOM_ENGINE.decode(wrong_encoded_salt);
// //     // println!("result: {:?}", result);
    
// //     // let mut bytes_aes_256_key: &[u8] = &[0u8];
// //     // // let salt = b"randomsalt";
// //     // let config = Config::default();
// //     // match settings {
// //     //     Ok(settings) => {
// //     //         let aes_256_key: &str = settings.get_aes_256_key();
// //     //         let salt: &str = settings.get_salt();
// //     //         // Use the key for encryption/decryption
// //     //         bytes_aes_256_key = aes_256_key.as_bytes();
// //     //         let hash = argon2::hash_encoded(bytes_aes_256_key, salt.as_bytes(), &config).unwrap();
// //     //         println!("hash: {:?}", hash);
// //     //         let matches = argon2::verify_encoded(&hash, bytes_aes_256_key).unwrap();
// //     //         assert!(matches);

// //     //         let decoded_key: Vec<u8> = CUSTOM_ENGINE.decode(aes_256_key).unwrap();
// //     //         println!("decoded_key {:?}", decoded_key);
// //     //     }
// //     //     Err(e) => {
// //     //         // Handle the error
// //     //     }
// //     // }

// //     // let rand_string: String = thread_rng()
// //     // .sample_iter(&Alphanumeric)
// //     // .take(10)
// //     // .map(char::from)
// //     // .collect();

// //     // println!("rand_string: {}", rand_string);
// //     let encoded_string: String = CUSTOM_ENGINE.encode("rWZWlViWfn");
// //     println!("encoded_string: {:?}", encoded_string);
// //     println!("string: {:?}", "rWZWlViWfn".as_bytes());
// //     let decode_salt = CUSTOM_ENGINE.decode(&encoded_string);
// //     println!("decode_salt: {:?}", decode_salt);
// //     assert_eq!(decode_salt.unwrap(), "rWZWlViWfn".as_bytes());

// //     let hashed_key: &str = "$argon2i$v=19$m=4096,t=3,p=1$cldaV2xWaVdmbg$I5O1IjynzqxxRZanKOYfBm3KpX4Z2g2wL93PKw0HDZ4";
// //     let encoded_salt: &str = "cldaV2xWaVdmbg";

// //     let test = CUSTOM_ENGINE.decode(encoded_salt).unwrap();
// //     println!("test: {:?}", test);
// //     assert_eq!(test, "rWZWlViWfn".as_bytes());

// // }