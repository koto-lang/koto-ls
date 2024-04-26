use tower_lsp::lsp_types::{Position, Range};

pub fn koto_span_to_lsp_range(span: koto::parser::Span) -> Range {
    Range {
        start: koto_to_lsp_position(span.start),
        end: koto_to_lsp_position(span.end),
    }
}

pub fn koto_to_lsp_position(position: koto::parser::Position) -> Position {
    Position {
        line: position.line,
        character: position.column,
    }
}

pub fn default<T: Default>() -> T {
    T::default()
}
