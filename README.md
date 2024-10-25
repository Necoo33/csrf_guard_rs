# Csrf Guard For All Runtimes And Frameworks

[csrf_guard](https://github.com/Necoo33/csrf_guard_rs) is a Thread safe, generic, enterprise level Csrf guard for all frameworks and runtimes. You can use it everywhere if you can reach guest ip and pass it as a String. You have two api options here: csrf_guard with expiration mechanism and without expiration. Their use is exactly same, but their constructors different.

## Breaking Changes

In this version, the [csrf_guard](https://github.com/Necoo33/csrf_guard_rs) took breaking changes, you have to do little refactor in your code. It's some functions and way of work changed drastically but the change of end-user experience is not as that big. Now you'll check the status of the token via `TokenStatus` enum, not by existance of token. It checks whether every token is expired or not in every request, even the request done by same ip or not, and if it's expired and not consumed until that moment, it's status value will be `TokenStatus::Expired` when it came to a protected route. If that ip enters a protected route [csrf_guard](https://github.com/Necoo33/csrf_guard_rs) knows it's an expired token.

By that update, [csrf_guard](https://github.com/Necoo33/csrf_guard_rs) took a big step towards became the most ideal solution for enterprise level software for csrf protection.

## Sample

In this example, we'll use Actix-web for back-end and Askama for template engine. But since it's a generic liblary, you can use it anywhere you want:

main.rs page:

```rust

use actix_web::{get, post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use askama::Template;
use serde;
use csrf_guard::{CsrfProtector, TokenStatus}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // initialize the protector in main function:

    // this is our new expiration api, you can give a timestamp with seconds:
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

    // entire change is about how you control csrf status:
    // control the token's status:
    return match unbound_protector.check_token_status(inputs.csrf_token.clone()) {
        TokenStatus::Exist => {
            // everytime when you control that token, don't forget the consume that token whether token is valid or not:
            unbound_protector.consume(inputs.csrf_token.clone());

            let response = ValidCsrfResponse {
                message: "Your Csrf Token Is Valid!".to_string()
            };

            HttpResponse::Ok().json(response)
        },
        TokenStatus::NotExist => {
            // consuming token
            unbound_protector.consume(inputs.csrf_token.clone());

            let response = InvalidCsrfResponse {
                message: "Bad Request: Invalid Csrf Token.".to_string()
            };

            HttpResponse::BadRequest().json(response)
        },
        TokenStatus::Expired => {
            // consuming token
            unbound_protector.consume(inputs.csrf_token.clone());

            let response = InvalidCsrfResponse {
                message: "Bad Request: Your Csrf Token Has been expired.".to_string()
            };

            HttpResponse::BadRequest().json(response)
        },
        TokenStatus::Unchecked => {
            // technically, its impossible to came here. If you reach there in any reason that means you encountered a bug. Please report it by opening an issue on github with demonstrating the bug:
            let response = InvalidCsrfResponse {
                message: "It's impossible to came here!".to_string()
            };

            HttpResponse::BadRequest().json(response)
        }
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

```

## Disclaimer

Although i tested it in many cases on my localhost, because it's complicated algorithm it could include logical bugs and not yet enoughly battle tested. If you encounter a bug, please feel free to open an issue on the [github repo](https://github.com/Necoo33/csrf_guard_rs). Any feature requests are welcome.
