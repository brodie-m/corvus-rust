use aws_config;
use aws_sdk_cognitoidentityprovider::model::UserType;
use aws_sdk_cognitoidentityprovider::Client as CognitoClient;
use aws_sdk_dynamodb::model::AttributeValue;
use aws_sdk_dynamodb::Client as DynamoClient;
use aws_sdk_lambda::model::InvocationType;
use aws_sdk_lambda::Client as LambdaClient;
use aws_smithy_types::Blob;
use lambda_http::http::Method;
use lambda_http::{
    service_fn, tower::ServiceBuilder, Body, Error, Request, RequestExt, Response,
};
use log::{debug,LevelFilter};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::env;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;
use async_once::AsyncOnce;
use lazy_static::{lazy_static};
use simple_logger::SimpleLogger;

//generate some static refs to config/client to improve warm start performance
lazy_static! {
    static ref CONFIG: AsyncOnce<aws_config::Config> = AsyncOnce::new(async {
        let config = aws_config::load_from_env().await;
        config
    });
    static ref DYNAMO_CLIENT: AsyncOnce<DynamoClient> = AsyncOnce::new(async {
        let client = DynamoClient::new(CONFIG.get().await);

        client
    });
    static ref COGNITO_CLIENT: AsyncOnce<CognitoClient> = AsyncOnce::new(async {
        let client = CognitoClient::new(CONFIG.get().await);

        client
    });
    static ref CORS_LAYER : AsyncOnce<CorsLayer> = AsyncOnce::new(async {
        let cors_layer = CorsLayer::new()
        .allow_methods(vec![Method::GET, Method::POST])
        .allow_origin(Any);
        cors_layer
    });
     
        
}


#[tokio::main]
async fn main() -> Result<(), Error> {
    //anything inside main will be kept warm inbetween invocations
    SimpleLogger::new().with_utc_timestamps().with_level(LevelFilter::Debug).init().unwrap();
    debug!("main started");
    let handler = ServiceBuilder::new()
        .layer(CORS_LAYER.get().await)
        .service(service_fn(generate_token));
    
    lambda_http::run(handler).await?;
    Ok(())
}


async fn generate_token(event: Request) -> Result<Response<Body>, Error> {
    debug!("generate token running");
    let ctx = event.request_context();

    //match only apigatewayv1 requests
    match ctx {
        lambda_http::request::RequestContext::ApiGatewayV1(x) => {
            let identity_info = x.identity;
            let token = generate_token_for_identity(identity_info).await?;
            Ok(Response::builder().status(200).body(token.into()).unwrap())
        },  
        _ => Ok(Response::builder()
            .status(400)
            .body("Not an ApiGatewayV1 request".into())
            .expect("failed to render response")),
    }
}

async fn generate_token_for_identity(
    identity_info: aws_lambda_events::apigw::ApiGatewayRequestIdentity,
) -> Result<String, Error> {
    let client = COGNITO_CLIENT.get().await;
    debug!("Now generating token...");

    //get necessary auth data
    let uuid = Uuid::new_v4().to_string();
    let role_name = extract_role_name(identity_info.user_arn.clone().unwrap());
    let mut auth_data = Map::new();
    let provider = identity_info.cognito_authentication_provider.clone().unwrap();
    let user_pool_info = extract_user_pool_info(provider);
    let user = get_user_attributes(&user_pool_info, client).await;
    let user_attributes = normalize_cognito_user_attributes(&user);

    //construct auth_data Map
    auth_data.insert("token".to_string(), json!(&uuid));
    auth_data.insert("identity_info".to_string(), json!(identity_info));
    auth_data.insert("role_name".to_string(), json!(role_name));
    auth_data.insert(
        "user_pool_info".to_string(),
        json!(""
        ),
    );
    auth_data.insert("user_attributes".to_string(), json!(user_attributes));
    auth_data.insert("connection_type".to_string(), json!(""));
    let auth_type = identity_info.cognito_authentication_type.clone().unwrap();
    if auth_type == "authenticated".to_string() {
        auth_data.insert("user_pool_info".to_string(), json!(user_pool_info));
    }
    auth_data.insert(
        "connection_type".to_string(),
        json!(identity_info.cognito_authentication_type),
    );
    let SHOULD_GET_APPLICATION_USER_PROFILE =
        env::var("SHOULD_GET_APPLICATION_USER_PROFILE").unwrap_or_else(|_| "".to_string());
    if auth_data.get("connection_type").unwrap() == &json!(&"authenticated")
        && SHOULD_GET_APPLICATION_USER_PROFILE == "true"
    {
        let profile = invoke_serverless_core_event(
            String::from("coreGetApplicationUserProfile"),
            &auth_data
        );
    }
    let SHOULD_BUILD_SECURE_CONNECTION_PARAMS =
        env::var("SHOULD_BUILD_SECURE_CONNECTION_PARAMS").unwrap_or_else(|_| "".to_string());
    if SHOULD_BUILD_SECURE_CONNECTION_PARAMS == "true" {
        let secure_params = invoke_serverless_core_event(
            String::from("coreBuildSecureConnectionParams"),
            &auth_data
        );
    }
    store_token(&auth_data, &user_attributes).await?;
    Ok(uuid)
}

fn extract_role_name(
    user_arn: String
) -> String {
    debug!("Extracting role name");
    let re = Regex::new(r"assumed-role/(.*)/").unwrap();
    let found = re.find(&user_arn).unwrap().as_str();
    let split = found.split('/');
    let vec = split.collect::<Vec<&str>>().clone();
    debug!("role name extracted");
    return vec[1].to_string();
}

fn extract_user_pool_info(auth_provider: String) -> [String; 2] {
    debug!("extracting user pool info");
    let user_pool_re = Regex::new(r".{2}-.{4}-.{1}_.*,").unwrap();
    let user_pool_user_re = Regex::new(r":.*-.*-.*-.*-.*").unwrap();
    let found_pool = user_pool_re.find(&auth_provider).unwrap().as_str();
    let found_pool_user = user_pool_user_re.find(&auth_provider).unwrap().as_str();
    debug!("Extracted user pool info");
    return [found_pool[0..found_pool.len()-1].to_string(), found_pool_user[15..].to_string()];
}

async fn get_user_attributes(user_pool_info: &[String; 2], client: &CognitoClient) -> UserType {
    debug!("Connecting to cognito...");
    let result = client
        .list_users()
        .user_pool_id(&user_pool_info[0])
        .filter(format!("sub = \"{}\"", user_pool_info[1]))
        .limit(1)
        .send()
        .await
        .unwrap();

    let user = &result.users().unwrap()[0];
    debug!("got stuff from cognito");
    return user.clone();
}

fn normalize_cognito_user_attributes(user: &UserType) -> HashMap<&str, String> {
    debug!("normalizingg user attrs");
    let attrs = user.attributes().unwrap();
    let mut attributes_map = HashMap::from([
        (
            "user_create_date",
            user.user_create_date().unwrap().as_secs_f64().to_string(),
        ),
        (
            "user_last_modified_date",
            user.user_last_modified_date()
                .unwrap()
                .as_secs_f64()
                .to_string(),
        ),
        ("enabled", user.enabled().to_string()),
        (
            "user_status",
            user.user_status().unwrap().as_str().to_string(),
        ),
    ]);
    for attribute in attrs {
        attributes_map.insert(
            &attribute.name.as_ref().unwrap(),
            attribute.value.as_ref().unwrap().to_string(),
        );
    }
    debug!("Attributes: {:?}", attributes_map);
    return attributes_map;
}

async fn store_token(
    auth_data: &Map<String, Value>,
    user_attributes: &HashMap<&str, String>,
) -> Result<(), Error> {
    debug!("starting to store token");
    let clone = auth_data.clone();
    debug!("getting client");
    let client =DYNAMO_CLIENT.get().await;
    debug!("finished getting client");

    //construct attribute values
    let mut attrs = HashMap::new();
    for (name, value) in user_attributes.into_iter() {
        attrs.insert(name.to_string(), AttributeValue::S(value.to_string()));
    }
    let identity_info = clone["identity_info"].as_object().unwrap();
    let mut id_info = HashMap::new();
    for (name, value) in identity_info.into_iter() {
        id_info.insert(name.to_string(), AttributeValue::S(value.as_str().unwrap_or_else(||"").to_string()));
    }
    
    let identity_info_av = AttributeValue::M(id_info);
    let token_av = AttributeValue::S(clone["token"].as_str().unwrap().to_string());
    let role_name_av = AttributeValue::S(clone["role_name"].as_str().unwrap().to_string());
    let attributes = HashMap::from([
        ("Attributes".to_string(),AttributeValue::M(attrs))
    ]);
    let attributes_av = AttributeValue::M(attributes);
    debug!("starting request");
    let _request = client
        .put_item()
        // hard coded for now but just use env
        .table_name("lpb-benchmark-corvus-auth-tokens-mcguire")
        .item("pk", token_av)
        .item("identityInfo", identity_info_av)
        .item("roleName", role_name_av)
        .item("userAttributes", attributes_av)
        .send()
        .await;
    debug!("token stored");
    Ok(())
}

async fn invoke_serverless_core_event(
    event_name: String,
    payload: &Map<String, Value>,
) -> Result<(), Error> {
    let client = LambdaClient::new(CONFIG.get().await);
    let name = format!(
        "{:?}-{:?}-{:?}",
        env::var("projectName"),
        env::var("stage"),
        event_name
    );
    let blob = serde_json::to_vec(&payload).unwrap();
    debug!("invoking event {:?} with payload {:?}", event_name, blob);
    client
        .invoke()
        .function_name(name)
        .invocation_type(InvocationType::from("RequestResponse"))
        .payload(Blob::new(blob));
    Ok(())
}

