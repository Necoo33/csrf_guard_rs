use std::sync::{Arc, Mutex};
use uuid;

#[derive(Debug, Clone)]
pub struct CsrfProtector {
    tokens: Vec<Csrf>,
}

impl CsrfProtector {
    // because of rust's synthax, we need this dummy Csrf instance to init 
    // protector: 

    pub fn init() -> Arc<Mutex<Self>> {
        let boilerplate_entry = Csrf {
            token: "".to_string(),
            ip: "".to_string()
        };

        let instance = Self {
            tokens: vec![boilerplate_entry]
        };

        return Arc::new(Mutex::new(instance))
    }

    // For handling csrf works, use that function later than getting actual instance 
    // with providing ip value as string:

    pub fn handle(&mut self, ip: String) -> Csrf {
        return self.perform_csrf_action(ip);
    }

    // Later than checking the sent token is valid, use that
    // function to remove that token for a specific ip: 
    pub fn consume(&mut self, token: String) -> Self {
        self.tokens.retain( | csrf | csrf.token != token);

        return Self {
            tokens: self.tokens.clone()
        }
    }

    // helper functions:

    // This function creates a new Csrf instance and adds it to
    // that protector and returns that instance: 
    fn add_new_csrf(&mut self, new_ip: String) -> Csrf {
        let new_csrf =  Csrf::create(new_ip);

        self.tokens.push(new_csrf.clone());

        return new_csrf
    }

    // this function checks if a Csrf instance has given ip:
    fn check_if_ip_exist(&self, current_ip: String) -> bool {
        for csrf in self.tokens.clone().into_iter() {
            if csrf.ip == current_ip {
                return true;
            }
        }

        return false;
    }

    // this function checks if a Csrf instance has given token:
    pub fn check_if_token_exist(&self, current_token: String) -> bool {
        for csrf in self.tokens.clone().into_iter() {
            if csrf.token == current_token {
                return true;
            }
        }

        return false;
    }

    // this function performs the check action. If there is no
    // Csrf instance that has same ip with given ip exist, then creates
    // a new instance and adds it to protector, if it exist
    // returns the Csrf instance that has same ip with given ip:
    fn perform_csrf_action(&mut self, ip: String) -> Csrf {
        if !self.check_if_ip_exist(ip.clone()) {
            return self.add_new_csrf(ip);
        } else {
            for csrf in self.tokens.clone().into_iter() {
                if csrf.ip == ip {
                    return csrf
                }
            }
        }

        return Csrf {
            token: "".to_string(),
            ip: "999.999.999.999".to_string()
        }
    }
}

// individual Csrf token to assign:

#[derive(Debug, Clone)]
pub struct Csrf {
    pub token: String,
    pub ip: String,
}

impl Csrf {
    pub fn create(ip: String) -> Self {
        return Self {
            token: uuid::Uuid::new_v4().to_string(),
            ip,
        }
    }
}
