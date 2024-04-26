use crate::source_info::SourceInfo;
use crate::utils::{default, koto_span_to_lsp_range};
use koto::bytecode::Compiler;
use koto::parser::{Parser, Span};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer};

pub struct KotoServer {
    client: Client,
    source_info: Arc<Mutex<HashMap<Url, SourceInfo>>>,
}

impl KotoServer {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            source_info: Arc::new(Mutex::new(HashMap::default())),
        }
    }

    async fn compile(&self, script: &str, uri: Url, version: i32) {
        self.source_info.lock().await.remove(&uri);
        let ast = match Parser::parse(script) {
            Ok(ast) => ast,
            Err(e) => {
                self.report_koto_error(e.span, e.error.to_string(), uri, version)
                    .await;
                return;
            }
        };
        if let Err(e) = Compiler::compile(&ast, default()) {
            self.report_koto_error(e.span, e.to_string(), uri, version)
                .await;
            return;
        }
        self.client
            .publish_diagnostics(uri.clone(), vec![], Some(version))
            .await;
        self.source_info
            .lock()
            .await
            .insert(uri, SourceInfo::from_ast(&ast));
    }

    async fn report_koto_error(&self, span: Span, message: String, uri: Url, version: i32) {
        let diagnostics = vec![Diagnostic {
            range: koto_span_to_lsp_range(span),
            message,
            ..default()
        }];

        self.client
            .publish_diagnostics(uri, diagnostics, Some(version))
            .await;
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
                definition_provider: Some(OneOf::Left(true)),
                ..default()
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

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> Result<Option<GotoDefinitionResponse>> {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;
        let result = self
            .source_info
            .lock()
            .await
            .get(&uri)
            .and_then(|info| info.get_reference(position))
            .map(|reference| {
                let location = Location {
                    uri: uri.clone(),
                    range: reference.definition,
                };
                GotoDefinitionResponse::Scalar(location)
            });

        if result.is_none() {
            self.client
                .log_message(
                    MessageType::INFO,
                    format!(
                        "source_info: {:?}",
                        self.source_info.lock().await.get(&uri).unwrap()
                    ),
                )
                .await;
            self.client
                .log_message(MessageType::INFO, "No definition found")
                .await;
        }

        Ok(result)
    }
}
