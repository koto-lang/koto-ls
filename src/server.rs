use crate::info_cache::InfoCache;
use crate::source_info::SourceInfo;
use crate::utils::{default, koto_span_to_lsp_range};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_lsp_server::jsonrpc::{Error, Result};
use tower_lsp_server::lsp_types::*;
use tower_lsp_server::{Client, LanguageServer};

pub struct KotoServer {
    client: Client,
    source_info: Arc<Mutex<InfoCache>>,
}

impl KotoServer {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            source_info: Arc::new(Mutex::new(InfoCache::default())),
        }
    }

    async fn compile(&self, script: String, uri: Uri, version: i32) {
        if self
            .source_info
            .lock()
            .await
            .get_versioned(&uri, version.into())
            .is_some()
        {
            return;
        }

        let uri_arc = Arc::new(uri.clone());
        let mut info_cache = self.source_info.lock().await;
        let info = SourceInfo::new(script, uri_arc.clone(), &mut info_cache);

        let diagnostics = if let Some(error) = &info.error {
            if let Some(span) = error.span() {
                vec![Diagnostic {
                    range: koto_span_to_lsp_range(span),
                    message: error.to_string(),
                    severity: Some(DiagnosticSeverity::ERROR),
                    ..default()
                }]
            } else {
                self.client
                    .log_message(MessageType::ERROR, error.to_string())
                    .await;
                return;
            }
        } else {
            vec![]
        };

        info_cache.insert(uri_arc, version.into(), info);

        self.client
            .publish_diagnostics(uri.clone(), diagnostics, Some(version))
            .await;
    }
}

impl LanguageServer for KotoServer {
    async fn initialize(&self, _: InitializeParams) -> Result<InitializeResult> {
        Ok(InitializeResult {
            server_info: None,
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                definition_provider: Some(OneOf::Left(true)),
                document_symbol_provider: Some(OneOf::Left(true)),
                references_provider: Some(OneOf::Left(true)),
                document_highlight_provider: Some(OneOf::Left(true)),
                rename_provider: Some(OneOf::Right(RenameOptions {
                    prepare_provider: Some(true),
                    work_done_progress_options: WorkDoneProgressOptions::default(),
                })),
                document_formatting_provider: Some(OneOf::Left(true)),
                ..default()
            },
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "initialized")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let doc = params.text_document;
        self.compile(doc.text, doc.uri, doc.version).await;
    }

    async fn did_change(&self, mut params: DidChangeTextDocumentParams) {
        let change = params.content_changes.swap_remove(0);
        let doc = params.text_document;
        self.compile(change.text, doc.uri, doc.version).await;
    }

    async fn hover(&self, params: HoverParams) -> Result<Option<Hover>> {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        let lock_await = self.source_info.lock().await;
        let result = lock_await.get(&uri).and_then(|info| {
            info.get_referenced_definition_location(position)
                .and_then(|location| {
                    if location.uri.as_ref() == &uri {
                        info.get_definition_from_location(location)
                            .map(|definition| {
                                format!(
                                    "**{}**  \n{:?} reference",
                                    definition.id.as_str(),
                                    definition.kind,
                                )
                            })
                    } else {
                        lock_await.get(&location.uri).and_then(|info| {
                            // Module reference
                            if location.range.end.character == 0 && location.range.end.line == 0 {
                                // TODO: proper way to handle module names
                                None
                            } else {
                                info.get_definition_from_location(location)
                                    .map(|definition| {
                                        format!(
                                            "**{}**  \n{:?} reference (from module)",
                                            definition.id.as_str(),
                                            definition.kind,
                                        )
                                    })
                            }
                        })
                    }
                })
                .or_else(|| {
                    info.get_definition_from_position(position)
                        .map(|definition| {
                            format!(
                                "**{}**  \n{:?} definition",
                                definition.id.as_str(),
                                definition.kind,
                            )
                        })
                })
        });

        Ok(if result.is_none() {
            self.client
                .log_message(MessageType::INFO, "No definition found")
                .await;
            None
        } else {
            result.map(|text| Hover {
                contents: HoverContents::Scalar(MarkedString::String(text)),
                range: None,
            })
        })
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
            .and_then(|info| info.get_definition_location(position))
            .map(|definition| GotoDefinitionResponse::Scalar(definition.into()));

        if result.is_none() {
            self.client
                .log_message(MessageType::INFO, "No definition found")
                .await;
        }

        Ok(result)
    }

    async fn document_symbol(
        &self,
        params: DocumentSymbolParams,
    ) -> Result<Option<DocumentSymbolResponse>> {
        let uri = params.text_document.uri;
        let result = self.source_info.lock().await.get(&uri).map(|info| {
            let definitions = info
                .top_level_definitions()
                .map(DocumentSymbol::from)
                .collect();
            DocumentSymbolResponse::Nested(definitions)
        });

        Ok(result)
    }

    async fn references(&self, params: ReferenceParams) -> Result<Option<Vec<Location>>> {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;
        let include_declaration = params.context.include_declaration;

        let Some(info) = self.source_info.lock().await.get(&uri) else {
            self.client
                .log_message(MessageType::ERROR, "No references found")
                .await;
            return Err(Error::invalid_params("No source information available"));
        };

        let result = info
            .find_references(position, include_declaration)
            .map(|references| references.map(Location::from).collect());

        if result.is_none() {
            self.client
                .log_message(MessageType::INFO, "No references found")
                .await;
        }

        Ok(result)
    }

    async fn document_highlight(
        &self,
        params: DocumentHighlightParams,
    ) -> Result<Option<Vec<DocumentHighlight>>> {
        let uri = params.text_document_position_params.text_document.uri;
        let position = params.text_document_position_params.position;

        let Some(info) = self.source_info.lock().await.get(&uri) else {
            self.client
                .log_message(MessageType::ERROR, "No references found")
                .await;
            return Err(Error::invalid_params("No source information available"));
        };

        let result = info.find_references(position, true).map(|references| {
            references
                .filter(|location| *location.uri == uri)
                .map(|location| DocumentHighlight {
                    range: location.range,
                    kind: None,
                })
                .collect()
        });

        if result.is_none() {
            self.client
                .log_message(MessageType::INFO, "No references found")
                .await;
        }

        Ok(result)
    }

    async fn formatting(&self, params: DocumentFormattingParams) -> Result<Option<Vec<TextEdit>>> {
        let uri = params.text_document.uri;

        let format_options = koto_format::FormatOptions {
            indent_width: params.options.tab_size as u8,
            ..Default::default()
        };

        let Some(info) = self.source_info.lock().await.get(&uri) else {
            self.client
                .log_message(MessageType::ERROR, "No references found")
                .await;
            return Err(Error::invalid_params("No source information available"));
        };

        match koto_format::format(info.source(), format_options) {
            Ok(formatted) => {
                let edit = TextEdit::new(
                    Range::new(Position::new(0, 0), Position::new(u32::MAX, u32::MAX)),
                    formatted,
                );
                Ok(Some(vec![edit]))
            }
            Err(e) => {
                self.client
                    .log_message(MessageType::ERROR, e.to_string())
                    .await;
                Ok(None)
            }
        }
    }

    async fn prepare_rename(
        &self,
        params: TextDocumentPositionParams,
    ) -> Result<Option<PrepareRenameResponse>> {
        let uri = params.text_document.uri;
        let position = params.position;

        let location = self
            .source_info
            .lock()
            .await
            .get(&uri)
            .and_then(|info| info.get_definition_location(position));

        if let Some(location) = location {
            if location.uri.as_ref() == &uri {
                Ok(Some(PrepareRenameResponse::Range(location.range)))
            } else {
                // The definition is in another file, don't allow a rename
                Ok(None)
            }
        } else {
            Err(Error::invalid_params("No reference found at position"))
        }
    }

    async fn rename(&self, params: RenameParams) -> Result<Option<WorkspaceEdit>> {
        let uri = params.text_document_position.text_document.uri;
        let position = params.text_document_position.position;
        let source_info = self.source_info.lock().await;
        if let Some(info) = source_info.get(&uri) {
            let Some(references) = info.find_references(position, true) else {
                return Err(Error::invalid_params("No reference found at position"));
            };

            let mut changes = HashMap::new();
            for reference in references {
                changes
                    .entry(reference.uri.as_ref().clone())
                    .or_insert_with(Vec::new)
                    .push(TextEdit {
                        range: reference.range,
                        new_text: params.new_name.clone(),
                    });
            }

            let result = WorkspaceEdit {
                changes: Some(changes),
                ..default()
            };

            Ok(Some(result))
        } else {
            Err(Error::invalid_params("No source info for file"))
        }
    }
}
