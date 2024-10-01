use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid;

#[derive(Debug, Clone)]
pub struct CsrfProtector {
    tokens: Vec<Csrf>,
    expiration_time: Option<Duration>
}

impl CsrfProtector {
    // because of rust's synthax, we need this dummy Csrf instance to init protector. 

    // create an instance without expiration:
    pub fn init() -> Arc<Mutex<Self>> {
        let boilerplate_entry = Csrf {
            token: "".to_string(),
            ip: "".to_string(),
            expiration: None
        };

        let instance = Self {
            tokens: vec![boilerplate_entry],
            expiration_time: None
        };

        return Arc::new(Mutex::new(instance))
    }

    // if you want to enable expiration for guard, use this constructor:
    pub fn init_with_expiration(seconds: u64) -> Arc<Mutex<Self>> {
        let boilerplate_entry = Csrf {
            token: "".to_string(),
            ip: "".to_string(),
            expiration: None
        };

        let instance = Self {
            tokens: vec![boilerplate_entry],
            expiration_time: Some(Duration::from_secs(seconds))
        };

        return Arc::new(Mutex::new(instance))
    }

    // For handling csrf works, use that function later than getting actual instance 
    // with providing ip value as string:

    pub fn handle(&mut self, ip: String) -> Csrf {
        return self.perform_csrf_action(ip);
    }

    // in this release, consume method is became a wrapper
    // for consume_inner method, because we use consuming
    // mechanism on other methods of that struct.

    // Later than checking the sent token is valid, use that
    // function to remove that token for a specific ip: 
    pub fn consume(&mut self, token: String) -> Self {
        return self.consume_inner(token)
    }

    fn consume_inner(&mut self, token: String) -> Self {
        self.tokens.retain( | csrf | csrf.token != token);

        return Self {
            tokens: self.tokens.clone(),
            expiration_time: self.expiration_time.clone()
        }
    }

    // helper functions:

    // This function creates a new Csrf instance and adds it to
    // that protector and returns that instance: 
    fn add_new_csrf(&mut self, new_ip: String) -> Csrf {
        let new_csrf;
        
        if self.expiration_time.is_some() {
            new_csrf = Csrf::init(new_ip).set_expiration_secs(self.expiration_time.unwrap())
        } else {
            new_csrf =  Csrf::init(new_ip);
        }

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
    // a new instance and adds it to protector, if it exist then
    // checks whether is token is expired or not; if it expired
    // it'll consume that token and create a new one, if it's not
    // expired returns the initial Csrf instance that has same 
    // ip with given ip:
    fn perform_csrf_action(&mut self, ip: String) -> Csrf {
        if !self.check_if_ip_exist(ip.clone()) {   
            return self.add_new_csrf(ip);
        } else {
            let mut current_csrf: Option<Csrf> = None;
            for csrf in self.tokens.clone().into_iter() {
                if self.expiration_time.is_some() {
                    if csrf.token == "" {
                        continue;
                    }

                    if let Some(expiration) = csrf.expiration {
                        if Instant::now() >= expiration {
                            if csrf.ip != ip {
                                self.consume_inner(csrf.token.clone());

                                self.add_new_csrf(ip.clone());
                            } else {
                                self.consume_inner(csrf.token.clone());

                                current_csrf = Some(self.add_new_csrf(ip.clone()));
                            }
                        }
                    }
                } else {
                    if csrf.ip == ip {
                        return csrf
                    }
                }
            }

            if current_csrf.is_some() {
                return current_csrf.unwrap()
            }
        }

        Csrf {
            token: "".to_string(),
            ip: "".to_string(),
            expiration: None
        }
    }
}

// individual Csrf token to assign:

#[derive(Debug, Clone)]
pub struct Csrf {
    pub token: String,
    pub ip: String,
    pub expiration: Option<Instant>
}

impl Csrf {
    fn init(ip: String) -> Self {
        return Self {
            token: uuid::Uuid::new_v4().to_string(),
            ip,
            expiration: None
        }
    }

    fn set_expiration_secs(&self, seconds: Duration) -> Self {
        return Self {
            token: self.token.clone(),
            ip: self.ip.clone(),
            expiration: Some(Instant::now() + seconds)
        }
    }
}
