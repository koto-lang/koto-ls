use tower_lsp_server::lsp_types::{CompletionItemKind, Position, Range, SymbolKind};

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

pub fn symbol_kind_to_completion_item_kind(symbol_kind: SymbolKind) -> CompletionItemKind {
    match symbol_kind {
        SymbolKind::FILE => CompletionItemKind::FILE,
        SymbolKind::MODULE => CompletionItemKind::MODULE,
        SymbolKind::NAMESPACE => CompletionItemKind::MODULE,
        SymbolKind::PACKAGE => CompletionItemKind::MODULE,
        SymbolKind::CLASS => CompletionItemKind::CLASS,
        SymbolKind::METHOD => CompletionItemKind::METHOD,
        SymbolKind::PROPERTY => CompletionItemKind::PROPERTY,
        SymbolKind::FIELD => CompletionItemKind::FIELD,
        SymbolKind::CONSTRUCTOR => CompletionItemKind::CONSTRUCTOR,
        SymbolKind::ENUM => CompletionItemKind::ENUM,
        SymbolKind::INTERFACE => CompletionItemKind::INTERFACE,
        SymbolKind::FUNCTION => CompletionItemKind::FUNCTION,
        SymbolKind::VARIABLE => CompletionItemKind::VARIABLE,
        SymbolKind::CONSTANT => CompletionItemKind::CONSTANT,
        SymbolKind::STRING => CompletionItemKind::VALUE,
        SymbolKind::NUMBER => CompletionItemKind::VALUE,
        SymbolKind::BOOLEAN => CompletionItemKind::VALUE,
        SymbolKind::ARRAY => CompletionItemKind::VALUE,
        SymbolKind::OBJECT => CompletionItemKind::VALUE,
        SymbolKind::KEY => CompletionItemKind::KEYWORD,
        SymbolKind::NULL => CompletionItemKind::VALUE,
        SymbolKind::ENUM_MEMBER => CompletionItemKind::ENUM_MEMBER,
        SymbolKind::STRUCT => CompletionItemKind::STRUCT,
        SymbolKind::EVENT => CompletionItemKind::EVENT,
        SymbolKind::OPERATOR => CompletionItemKind::OPERATOR,
        SymbolKind::TYPE_PARAMETER => CompletionItemKind::TYPE_PARAMETER,
        _ => CompletionItemKind::VALUE,
    }
}