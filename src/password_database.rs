use ring::{digest, pbkdf2};
use ring::rand::{SystemRandom, SecureRandom};
use std::{collections::HashMap, num::NonZeroU32};
use serde::{Serialize, Deserialize};
use rand::prelude::IteratorRandom;

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;
const SALT_LEN: usize = 16;
pub type Credential = [u8; CREDENTIAL_LEN];

pub enum Error {
    WrongPassword,
    AccountDoesNotExist,
}

#[derive(Serialize, Deserialize, Debug)]
struct SaltedCredential {
    credential: Credential,
    salt: [u8; SALT_LEN],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PasswordDatabase {
    iterations: NonZeroU32,
    db_salt: [u8; SALT_LEN],
    storage: HashMap<String, SaltedCredential>,
    #[serde(skip)]
    master_password: String,
}

impl PasswordDatabase {
    pub fn new(iterations: NonZeroU32) -> PasswordDatabase {
        let rnd = SystemRandom::new();
        let mut salt = [0u8; SALT_LEN];
        rnd.fill(&mut salt).unwrap();
        return PasswordDatabase {
            iterations: iterations,
            db_salt: salt,
            storage: HashMap::new(),
            master_password: String::from(""),
        };
    }

    pub fn set_master_password(&mut self, master_password: String) {
        self.master_password = master_password;
    }

    pub fn store_password(&mut self, username: &str, password: &str) {
        let mut account_salt = [0u8; SALT_LEN];
        let rnd = SystemRandom::new();
        rnd.fill(&mut account_salt).unwrap();
        let salt = self.salt(&account_salt);

        let mut to_store: Credential = [0u8; CREDENTIAL_LEN];
        pbkdf2::derive(PBKDF2_ALG, self.iterations, &salt,
                       password.as_bytes(), &mut to_store);

        self.storage.insert(String::from(username), SaltedCredential {
            credential: to_store,
            salt: account_salt,
        });
    }

    pub fn remove_password(&mut self, username: &str) {
        self.storage.remove(username);
    }

    pub fn verify_password(&self, username: &str, attempted_password: &str) -> Result<(), Error> {
        match self.storage.get(username) {
           Some(salted_credential) => {
               let salt = self.salt(&salted_credential.salt);
               pbkdf2::verify(PBKDF2_ALG, self.iterations, &salt,
                              attempted_password.as_bytes(),
                              &salted_credential.credential)
                    .map_err(|_| Error::WrongPassword)
           },

           None => Err(Error::AccountDoesNotExist)
        }
    }

    pub fn get_random_username(&self) -> Option<&String> {
        self.storage.keys().choose(&mut rand::thread_rng())
    }

    pub fn contains_username(&self, username: &String) -> bool {
        self.storage.contains_key(username)
    }

    fn salt(&self, account_salt: &[u8]) -> Vec<u8> {
        let masterbytes = self.master_password.as_bytes();
        let mut salt = Vec::with_capacity(self.db_salt.len() + account_salt.len() + masterbytes.len());
        salt.extend(&self.db_salt);
        salt.extend(account_salt);
        salt.extend(masterbytes);
        salt
    }

    pub fn num_accounts(&self) -> usize {
        self.storage.len()
    }

    pub fn get_hashed_master_password(&self) -> String {
        let mut to_store: Credential = [0u8; CREDENTIAL_LEN];
        pbkdf2::derive(PBKDF2_ALG, self.iterations, &self.db_salt, self.master_password.as_bytes(), &mut to_store);
        to_store.iter().take(3).map(|b| format!("{:02x}", b)).collect()
    }
}
