use tower_lsp_server::lsp_types::{Position, Range};

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
