mod server;
mod source_info;
mod utils;
mod info_cache;

use crate::server::KotoServer;
use tower_lsp::{LspService, Server};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();
    let (stdin, stdout) = (tokio::io::stdin(), tokio::io::stdout());
    let (service, socket) = LspService::new(KotoServer::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}
