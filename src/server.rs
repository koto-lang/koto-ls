use std::sync::Arc;

use koto::Koto;
use parking_lot::Mutex;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};

pub struct KotoServer {
    client: Client,
    koto: Arc<Mutex<Koto>>,
}

impl KotoServer {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            koto: Arc::new(Mutex::new(Koto::default())),
        }
    }

    async fn compile(&self, script: &str, uri: Url, version: i32) {
        let result = self.koto.lock().set_script_path(uri.to_file_path().ok());
        if let Err(e) = result {
            self.client.log_message(MessageType::ERROR, e).await;
            return;
        }
        let result = self.koto.lock().compile(script);
        match result {
            Ok(_) => {
                self.client
                    .publish_diagnostics(uri, vec![], Some(version))
                    .await;
            }
            Err(koto::Error {
                error: koto::ErrorKind::CompileError(e),
                ..
            }) => {
                if let Some(source) = e.source {
                    let diagnostics = vec![Diagnostic {
                        range: koto_span_to_lsp_range(source.span),
                        message: e.error.to_string(),
                        ..Default::default()
                    }];

                    self.client
                        .log_message(MessageType::INFO, "Error, sending diagnostics")
                        .await;
                    self.client
                        .publish_diagnostics(uri, diagnostics, Some(version))
                        .await;
                }
            }
            Err(e) => {
                self.client.log_message(MessageType::ERROR, e).await;
            }
        }
    }
}

fn koto_span_to_lsp_range(span: koto::parser::Span) -> Range {
    Range {
        start: Position {
            line: span.start.line - 1,
            character: span.start.column - 1,
        },
        end: Position {
            line: span.end.line - 1,
            character: span.end.column - 1,
        },
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for KotoServer {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            server_info: None,
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                ..ServerCapabilities::default()
            },
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "initialized!")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        self.client
            .log_message(MessageType::INFO, "file opened!")
            .await;

        let doc = params.text_document;
        self.compile(&doc.text, doc.uri, doc.version).await;
    }

    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        self.client
            .log_message(MessageType::INFO, "file changed!")
            .await;
        if let Some(change) = params.content_changes.first() {
            let doc = params.text_document;
            self.compile(&change.text, doc.uri, doc.version).await;
        } else {
            self.client
                .log_message(MessageType::INFO, "No changes?")
                .await;
        }
    }
}
