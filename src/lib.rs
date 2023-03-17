#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
extern crate crypto;
extern crate base64;

pub mod config;

pub mod crypto_service {
    use anyhow::{anyhow, Result};
    use base64::{Engine as _, engine::{self, general_purpose}, alphabet};
    use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
    use crypto::{aes, blockmodes, buffer};
    use crate::config::ConfigService;
    use rand::{thread_rng, Rng};
    use rand::distributions::Alphanumeric;

    #[derive(Clone, Debug, Default)]
    pub struct Aes256 {}

    impl Aes256 {
        pub fn create_key(&self) -> Result<(String, String)> {
            const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
    
            let mut key: [u8; 32] = [0u8; 32];
            let mut salt: [u8; 14] = [0u8; 14];
            thread_rng().fill(&mut key[..]);
            thread_rng().fill(&mut salt[..]);
    
            let encoded_key: String = CUSTOM_ENGINE.encode(&key);
            let encoded_salt: String = CUSTOM_ENGINE.encode(&salt);
            Ok((encoded_key, encoded_salt))
        }

        /// Encrypts a buffer with the given key and nonce using
        /// AES-256/CBC/Pkcs encryption.
        ///
        /// # Parameters
        /// - `nonce`: The nonce to be used for encryption. Must be 12 bytes long.
        /// - `secret`: The plaintext buffer to be encrypted.
        ///
        /// # Returns
        /// - `Vec<u8>`: The encrypted data.
        ///
        /// # Errors
        /// - If the nonce is not 12 bytes long, returns an error.
        /// - If nonce all be zero's return an error
        /// - If secret is empty return an error
        /// - If the secret is too large, returns an error.
        pub fn encrypt(&self, nonce: &[u8; 12], secret: &[u8; 12]) -> Result<Vec<u8>> {
            if nonce.len() != 12 {
                return Err(anyhow::anyhow!("Invalid nonce size: {} bytes, expected 12 bytes", nonce.len()));
            }

            if nonce.iter().all(|&x| x == 0) {
                return Err(anyhow::anyhow!("Nonce is not secure, nonce must not be all zeros"));
            }

            if secret.is_empty() {
                return Err(anyhow::anyhow!("secret buffer is empty"));
            }
            if secret.len() > 12 {
                return Err(anyhow::anyhow!("plaintext buffer is too large, maximum size is 12 bytes"));
            }

            let mut encryptor =
            aes::cbc_encryptor(aes::KeySize::KeySize256, &self.key, nonce, blockmodes::PkcsPadding);

            let mut final_result: Vec<u8> = Vec::<u8>::new();
            let mut read_buffer: buffer::RefReadBuffer = buffer::RefReadBuffer::new(secret);
            let mut buffer: [u8; 4096] = [0; 4096];
            let mut write_buffer:buffer::RefWriteBuffer = buffer::RefWriteBuffer::new(&mut buffer);
            loop {
                let result: BufferResult = encryptor
                    .encrypt(&mut read_buffer, &mut write_buffer, true)
                    .expect("Error encrypting data");
    
                final_result.extend(
                    write_buffer
                        .take_read_buffer()
                        .take_remaining()
                        .iter()
                        .map(|&i| i),
                );
    
                match result {
                    BufferResult::BufferUnderflow => break,
                    BufferResult::BufferOverflow => {}
                }
            }
            Ok(final_result)
        }

        /// Decrypts a buffer with the given key and nonce using
        /// AES-256/CBC/Pkcs encryption.
        ///
        /// # Parameters
        /// - `nonce`: The nonce used for encryption. Must be 12 bytes long.
        /// - `encrypted_data`: The encrypted data to be decrypted.
        ///
        /// # Returns
        /// - `Vec<u8>`: The decrypted data.
        ///
        /// # Errors
        /// - If the nonce is not 12 bytes long, returns an error.
        pub fn decrypt(&self, nonce: &[u8; 12], encrypted_data: &[u8])-> Result<Vec<u8>> {
            if encrypted_data.is_empty() {
                return Err(anyhow::anyhow!("Encrypted data buffer is empty"));
            }
            
            if encrypted_data.len() > 4096 {
                return Err(anyhow::anyhow!("Encrypted data buffer is too large, maximum size is 4096 bytes"));
            }

            let mut decryptor = aes::cbc_decryptor(aes::KeySize::KeySize256, &self.key, nonce, blockmodes::PkcsPadding);

            let mut final_result: Vec<u8> = Vec::<u8>::new();
            let mut read_buffer: buffer::RefReadBuffer = buffer::RefReadBuffer::new(encrypted_data);
            let mut buffer: [u8; 4096]  = [0; 4096];
            let mut write_buffer: buffer::RefWriteBuffer = buffer::RefWriteBuffer::new(&mut buffer);

            loop {
                let result: BufferResult = decryptor
                    .decrypt(&mut read_buffer, &mut write_buffer, true)
                    .expect("Error decrypting data");
                final_result.extend(
                    write_buffer
                        .take_read_buffer()
                        .take_remaining()
                        .iter()
                        .map(|&i| i),
                );
                match result {
                    BufferResult::BufferUnderflow => break,
                    BufferResult::BufferOverflow => {}
                }
            }
            Ok(final_result)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        // use rand::{thread_rng, Rng};


        // #[test]
        // fn test_new() {
        //     let hashed_key: &str = "$argon2i$v=19$m=4096,t=3,p=1$cldaV2xWaVdmbg$I5O1IjynzqxxRZanKOYfBm3KpX4Z2g2wL93PKw0HDZ4";
        //     let encoded_salt: &str = "cldaV2xWaVdmbg";
        //     let aes256: Aes256 = Aes256::new(hashed_key, encoded_salt).unwrap();
        //     assert_eq!(aes256.key.len(), 32);
        // }

        // #[test]
        // fn test_encrypt() {
        //     let mut nonce: [u8; 12] = [0u8; 12];
        //     thread_rng().fill(&mut nonce[..]);

        //     let hashed_key: &str = "$argon2i$v=19$m=4096,t=3,p=1$cldaV2xWaVdmbg$I5O1IjynzqxxRZanKOYfBm3KpX4Z2g2wL93PKw0HDZ4";
        //     let encoded_salt: &str = "cldaV2xWaVdmbg";
        //     let aes256: Aes256 = Aes256::new(hashed_key, encoded_salt).unwrap();

        //     let plaintext: &[u8; 12] = b"Hello World!";
        //     let encrypted_data: Vec<u8> = aes256.encrypt(&nonce, plaintext).unwrap();
        //     assert_eq!(encrypted_data.len(), plaintext.len() + 4);
        // }

        // #[test]
        // fn test_decrypt() {
        //     let mut nonce: [u8; 12] = [0u8; 12];
        //     thread_rng().fill(&mut nonce[..]);

        //     let hashed_key: &str = "$argon2i$v=19$m=4096,t=3,p=1$cldaV2xWaVdmbg$I5O1IjynzqxxRZanKOYfBm3KpX4Z2g2wL93PKw0HDZ4";
        //     let encoded_salt: &str = "cldaV2xWaVdmbg";
        //     let aes256: Aes256 = Aes256::new(hashed_key, encoded_salt).unwrap();
        //     let plaintext: &[u8; 12] = b"Hello World!";
        //     let encrypted_data: Vec<u8> = aes256.encrypt(&nonce, plaintext).unwrap();
        //     let decrypted_data:Vec<u8> = aes256.decrypt(&nonce, &encrypted_data).unwrap();

        //     // Check that the decrypted data is the same as the original plaintext
        //     assert_eq!(plaintext, &decrypted_data[..plaintext.len()]);
        // }
    }

}
