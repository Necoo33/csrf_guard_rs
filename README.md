# Csrf Guard For All Runtimes And Frameworks

[csrf_guard](https://github.com/Necoo33/csrf_guard_rs) is a Thread safe, generic Csrf guard for all frameworks and runtimes. You can use it everywhere if you can reach guest ip and pass it as a String. You have two api options here: csrf_guard with expiration mechanism and without expiration. Their use is exactly same, but their constructors different.

## Sample

In this example, we'll use Actix-web for back-end and Askama for template engine. But since it's a generic liblary, you can use it anywhere you want:

main.rs page:

```rust

use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use askama::Template;
use serde;
use csrf_guard::CsrfProtector

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // initialize the protector in main function:

    // this is our new expiration api, all tokens will be assigned with 1 hour timestamp:
    let new_protector = CsrfProtector::init_with_expiration(3600);

    // in actix-web, you'll share the state via "actix_web::app::App::app_data()" function,
    // because of that we used to pass our protector on that:
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(new_protector.clone()))  
            .service(home_controller)
            .service(post_controller)
    }).bind("127.0.0.1:4500")?.run().await?;

    Ok(())
}

// define an actix route:
#[get("/")]
pub async fn home_controller(req: HttpRequest, protector: web::Data<Arc<Mutex<CsrfProtector>>>) -> impl Responder {
    // this liblary took it's genericity from simply you have to manually pass ip of the user and in actix-web you can get it by that as String:
    let get_ip_address = req.peer_addr().unwrap().to_string();
    
    // since CsrfProtector is surrounded Arc type it should be unlocked before using it: 
    let mut get_app_state = protector.lock().unwrap();

    // then basically handle the all csrf work via handle function with passing guest id:
    let csrf = get_app_state.handle(get_ip_address);

    // sending data on template:
    let our_template = HomeTemplate {
        csrf: csrf.token
    };

    // create template:
    let template = our_template.render().unwrap();

    // return the response:
    HttpResponse::Ok().content_type("text/html").body(template)
}

#[post("/post")]
pub async fn post_controller(protector: web::Data<Arc<Mutex<CsrfProtector>>>, inputs: web::Form<PostInputs>) -> impl Responder {
    // get the protector state again. Do it first everytime when you want to control a csrf token:
    let mut unbound_protector = protector.lock().unwrap();

    // control if that token is exist:
    if !unbound_protector.check_if_token_exist(inputs.csrf_token.clone()) {
        // everytime when you control that token, don't forget the consume that token whether token is valid or not:
        unbound_protector.consume(inputs.csrf_token.clone());

        // since we want to have minimal and basic example, i added that struct and handled the sending response by that way for the sake of simplicity:
        let response = InvalidCsrfResponse {
            message: "Bad Request: Invalid Csrf Token.".to_string()
        };

        HttpResponse::BadRequest().json(response)
    } else {
        // consume your token everytime when you control it:
        unbound_protector.consume(inputs.csrf_token.clone());

        let response = ValidCsrfResponse {
            message: "Your Csrf Token Is Valid!".to_string()
        };

        HttpResponse::Ok().json(response)
    }
}

// put the "home.html" file into the /templates/pages folder.

#[derive(Template)]
#[template(path = "pages/home.html")]
pub struct HomeTemplate { 
    pub csrf: String
}

#[derive(Debug, serde::Deserialize)]
pub struct PostInputs {
    pub csrf_token: String
}

// that structs are optional but for the sake of simplicity i created them:

#[derive(Debug, serde::Serialize)]
pub struct InvalidCsrfResponse {
    pub message: String
}

#[derive(Debug, serde::Serialize)]
pub struct ValidCsrfResponse {
    pub message: String
}

```

Disclaimer: In this example, we sent the form with a basic html form but you can also do that via ajax or just sending request from server, there is no limitation about that.

Home.html file:

```html

<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Document</title>
    </head>
    <body>
        <h1>Hello!</h1>

        <form action="/post" method="post">
            <!-- put the csrf token on your form with a hidden input like that: -->
            <input type="hidden" name="csrf_token" value="{{ csrf }}">
            <input type="submit" value="send">
        </form>
    </body>
</html>

``
