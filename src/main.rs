mod info_cache;
mod server;
mod source_info;
mod utils;

use crate::server::KotoServer;
use tower_lsp_server::{LspService, Server};

#[tokio::main]
async fn main() {
    #[cfg(feature = "log")]
    {
        tracing_subscriber::fmt().init();
    }

    let (stdin, stdout) = (tokio::io::stdin(), tokio::io::stdout());
    let (service, socket) = LspService::new(KotoServer::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}
