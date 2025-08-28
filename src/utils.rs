use tower_lsp_server::lsp_types::{CompletionItemKind, Position, Range, SymbolKind};

use crate::source_info::SourceInfo;

pub fn koto_span_to_lsp_range(span: koto_parser::Span) -> Range {
    Range {
        start: koto_to_lsp_position(span.start),
        end: koto_to_lsp_position(span.end),
    }
}

pub fn koto_to_lsp_position(position: koto_parser::Position) -> Position {
    Position {
        line: position.line,
        character: position.column,
    }
}

pub fn default<T: Default>() -> T {
    T::default()
}

pub fn symbol_kind_to_completion_kind(symbol_kind: SymbolKind) -> CompletionItemKind {
    match symbol_kind {
        SymbolKind::FUNCTION => CompletionItemKind::FUNCTION,
        SymbolKind::VARIABLE => CompletionItemKind::VARIABLE,
        SymbolKind::FIELD => CompletionItemKind::FIELD,
        SymbolKind::NUMBER => CompletionItemKind::VALUE,
        SymbolKind::STRING => CompletionItemKind::VALUE,
        SymbolKind::BOOLEAN => CompletionItemKind::VALUE,
        SymbolKind::ARRAY => CompletionItemKind::VALUE,
        SymbolKind::OBJECT => CompletionItemKind::VALUE,
        SymbolKind::NULL => CompletionItemKind::VALUE,
        _ => CompletionItemKind::TEXT,
    }
}

#[allow(unused)]
pub fn print_defs_refs(info: &SourceInfo) {
    println!("Definitions:");
    for def in &info.definitions {
        println!(" - id: {} range: {:?}", def.id.as_str(), def.location.range);
    }

    println!("Definitions by Position:");
    for (range, id) in &info.definitions_by_range {
        println!(" - id: {} range: {:?}", id.0, range);
    }

    println!("References:");
    for refe in &info.references {
        println!(
            " - id: {} range: {:?}",
            refe.id.as_str(),
            refe.location.range
        );
        println!("  - definition range: {:?}", refe.definition.range);
    }

    println!("References by Position:");
    for (range, id) in &info.references_by_range {
        println!(" - id: {} range: {:?}", id.0, range);
    }
}

#[allow(unused)]
pub async fn ls_print_defs_refs(client: &tower_lsp_server::Client, info: &SourceInfo) {
    let mut defs = String::from("Definitions:\n");
    for def in &info.definitions {
        defs.push_str(&format!(
            " - id: {} range: {:?}\n",
            def.id.as_str(),
            def.location.range
        ));
    }
    client
        .log_message(tower_lsp_server::lsp_types::MessageType::INFO, defs)
        .await;

    let mut defs_by_pos = String::from("Definitions by Position:\n");
    for (pos, id) in &info.definitions_by_range {
        defs_by_pos.push_str(&format!("   - id: {} range: {:?}\n", id.0, pos));
    }
    client
        .log_message(tower_lsp_server::lsp_types::MessageType::INFO, defs_by_pos)
        .await;

    let mut refs = String::from("References:\n");
    for refe in &info.references {
        refs.push_str(&format!(
            " - id: {} range: {:?}\n",
            refe.id.as_str(),
            refe.location.range
        ));
        refs.push_str(&format!(
            "  - definition range: {:?}\n",
            refe.definition.range
        ));
    }
    client
        .log_message(tower_lsp_server::lsp_types::MessageType::INFO, refs)
        .await;

    let mut refs_by_pos = String::from("References by Position:\n");
    for (pos, id) in &info.references_by_range {
        refs_by_pos.push_str(&format!("   - id: {} range: {:?}\n", id.0, pos));
    }
    client
        .log_message(tower_lsp_server::lsp_types::MessageType::INFO, refs_by_pos)
        .await;
}
