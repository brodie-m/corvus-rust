# corvus-rust
- handlers for corvus written in Rust

## compiling
- I am using a modified version of serverless-rust and corvus to allow Rust handlers to be added in the usual way

## generate-token-rust
- generates a token with user attributes from cognito
- token is saved in dynamodb

### todo list:
- add expiry
- remove any hardcoding (table names etc)
- optimisation