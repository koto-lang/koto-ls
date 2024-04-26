#![allow(unused)]

use std::cmp::Ordering;

use anyhow::Result;
use koto::parser::{
    Ast, AstFor, AstIf, AstIndex, AstNode, AstString, AstTry, ConstantIndex, Function, IdOrString,
    LookupNode, MapKey, Node, Span, StringContents, StringNode,
};
use tower_lsp::lsp_types::{Location, Position, Range};

use crate::utils::koto_span_to_lsp_range;

#[derive(Clone, Debug, PartialEq)]
pub struct SourceInfo {
    // A vec of all known references, sorted by start position
    references: Vec<Reference>,
}

impl SourceInfo {
    pub fn from_ast(ast: &Ast) -> Self {
        let builder = SourceInfoBuilder::from_ast(ast);
        Self {
            references: builder.references,
        }
    }

    pub fn get_reference(&self, position: Position) -> Option<&Reference> {
        if let Ok(i) = self.references.binary_search_by(|reference| {
            let range = &reference.range;
            if position < range.start {
                Ordering::Greater
            } else if position >= range.end {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        }) {
            Some(&self.references[i])
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Reference {
    pub range: Range,
    pub definition: Range,
    pub id: ConstantIndex,
}

#[derive(Default)]
struct SourceInfoBuilder {
    frames: Vec<Frame>,
    references: Vec<Reference>,
}

impl SourceInfoBuilder {
    pub fn from_ast(ast: &Ast) -> Self {
        let mut result = Self::default();

        if let Some(entry_point) = ast.entry_point() {
            result.visit_node(entry_point, ast, false);
        };

        result
    }

    fn visit_node(&mut self, node_index: AstIndex, ast: &Ast, id_is_definition: bool) {
        let node = ast.node(node_index);
        match &node.node {
            // Nodes that can be skipped
            Node::Null
            | Node::BoolTrue
            | Node::BoolFalse
            | Node::SmallInt(_)
            | Node::Int(_)
            | Node::Float(_)
            | Node::RangeFull
            | Node::Continue
            | Node::Self_
            | Node::Wildcard(_) => {}
            // Nodes with a single child node that should be visited
            Node::Nested(node)
            | Node::RangeFrom { start: node }
            | Node::RangeTo { end: node, .. }
            | Node::UnaryOp { value: node, .. }
            | Node::Loop { body: node }
            | Node::Throw(node)
            | Node::Yield(node)
            | Node::Debug {
                expression: node, ..
            } => self.visit_node(*node, ast, false),
            // Nodes with a list of nodes that should be visited
            Node::List(nodes)
            | Node::Tuple(nodes)
            | Node::TempTuple(nodes)
            | Node::Block(nodes) => self.visit_nested(nodes, ast, false),
            // Nodes with an optional child node
            Node::Break(maybe_node) | Node::Return(maybe_node) => {
                if let Some(node) = maybe_node {
                    self.visit_node(*node, ast, false);
                }
            }
            Node::Id(id) => {
                if id_is_definition {
                    self.add_definition(*id, node, ast);
                } else {
                    self.add_reference(*id, node, ast);
                }
            }
            Node::Meta(_, _) => {
                // There may be something to do here with named meta entries?
            }
            Node::Lookup((lookup_node, next)) => {
                match lookup_node {
                    LookupNode::Root(root) => self.visit_node(*root, ast, false),
                    LookupNode::Id(id) => self.add_reference(*id, node, ast),
                    LookupNode::Str(s) => self.visit_string(s, ast),
                    LookupNode::Index(node) => self.visit_node(*node, ast, false),
                    LookupNode::Call { args, .. } => self.visit_nested(args, ast, false),
                }
                if let Some(next) = next {
                    self.visit_node(*next, ast, false);
                }
            }
            Node::NamedCall { id, args } => {
                self.add_reference(*id, node, ast);
                self.visit_nested(args, ast, false);
            }
            Node::Str(s) => self.visit_string(s, ast),
            Node::Range { start, end, .. } => {
                self.visit_node(*start, ast, false);
                self.visit_node(*end, ast, false);
            }
            Node::Map(entries) => {
                for (key, value) in entries.iter() {
                    match key {
                        MapKey::Str(s) => self.visit_string(s, ast),
                        MapKey::Id(id) => {
                            // Shorthand syntax?
                            if value.is_none() {
                                // TODO
                                // The id could be added as a reference if we had access to a span.
                            }
                        }
                        MapKey::Meta(_, _) => {
                            // There might be something to do here?
                        }
                    }
                    if let Some(value) = value {
                        self.visit_node(*value, ast, false);
                    }
                }
            }
            Node::MainBlock { body, local_count } => {
                self.frames.push(Frame::with_capacity(*local_count));
                self.visit_nested(body, ast, false);
                self.frames.pop();
            }
            Node::Function(info) => {
                self.frames
                    .push(Frame::with_capacity(info.local_count + info.args.len()));
                self.visit_nested(&info.args, ast, true);
                self.visit_node(info.body, ast, false);
                self.frames.pop();
            }
            Node::Import { from, items } => {
                for source in from.iter() {
                    match source {
                        IdOrString::Id(_) => {
                            // TODO - the from id could be added as a reference if we had a span
                        }
                        IdOrString::Str(s) => self.visit_string(s, ast),
                    }
                }
                for item in items.iter() {
                    match &item.item {
                        IdOrString::Id(_) => {
                            // TODO - the from id could be added as a reference if we had a span
                        }
                        IdOrString::Str(s) => self.visit_string(s, ast),
                    }
                    if let Some(_name) = item.name {
                        // TODO the 'as' name could be added as a definition if we had a span
                    }
                }
            }
            Node::Export(item) => {
                // Set id_is_definition to true to count exported map keys as definitions,
                // (currently this won't work because map keys don't have spans yet)
                self.visit_node(*item, ast, true);
            }
            Node::Assign { target, expression } => {
                self.visit_node(*target, ast, true);
                self.visit_node(*expression, ast, false);
            }
            Node::MultiAssign {
                targets,
                expression,
            } => {
                self.visit_nested(targets, ast, true);
                self.visit_node(*expression, ast, false);
            }
            Node::BinaryOp { op, lhs, rhs } => {
                self.visit_node(*lhs, ast, false);
                self.visit_node(*rhs, ast, false);
            }
            Node::If(info) => {
                self.visit_node(info.condition, ast, false);
                self.visit_node(info.then_node, ast, false);
                for (else_if_condition, else_if_block) in info.else_if_blocks.iter() {
                    self.visit_node(*else_if_condition, ast, false);
                    self.visit_node(*else_if_block, ast, false);
                }
                if let Some(else_node) = info.else_node {
                    self.visit_node(else_node, ast, false);
                }
            }
            Node::Match { expression, arms } => {
                self.visit_node(*expression, ast, false);
                for arm in arms.iter() {
                    for pattern in arm.patterns.iter() {
                        self.visit_node(*pattern, ast, true);
                    }
                    if let Some(condition) = arm.condition {
                        self.visit_node(condition, ast, false);
                    }
                    self.visit_node(arm.expression, ast, false);
                }
            }
            Node::Switch(arms) => {
                for arm in arms.iter() {
                    if let Some(condition) = arm.condition {
                        self.visit_node(condition, ast, false);
                    }
                    self.visit_node(arm.expression, ast, false);
                }
            }
            Node::Ellipsis(maybe_id) => {
                if let Some(id) = maybe_id {
                    if id_is_definition {
                        self.add_definition(*id, node, ast);
                    }
                }
            }
            Node::For(info) => {
                self.visit_nested(&info.args, ast, true);
                self.visit_node(info.iterable, ast, false);
                self.visit_node(info.body, ast, false);
            }
            Node::While { condition, body } | Node::Until { condition, body } => {
                self.visit_node(*condition, ast, false);
                self.visit_node(*body, ast, false);
            }
            Node::Try(info) => {
                self.visit_node(info.try_block, ast, false);
                self.visit_node(info.catch_arg, ast, true);
                self.visit_node(info.catch_block, ast, false);
                if let Some(finally_block) = info.finally_block {
                    self.visit_node(finally_block, ast, false);
                }
            }
        }
    }

    fn visit_nested(&mut self, nested: &[AstIndex], ast: &Ast, id_is_definition: bool) {
        for node in nested.iter() {
            self.visit_node(*node, ast, id_is_definition);
        }
    }

    fn add_definition(&mut self, id: ConstantIndex, node: &AstNode, ast: &Ast) {
        let span = ast.span(node.span);
        self.frames
            .last_mut()
            .expect("Missing frame")
            .add_definition(id, *span);
    }

    fn add_reference(&mut self, id: ConstantIndex, node: &AstNode, ast: &Ast) {
        for frame in self.frames.iter().rev() {
            if let Some(definition) = frame.get_definition(id) {
                let span = ast.span(node.span);
                self.references.push(Reference {
                    range: koto_span_to_lsp_range(*span),
                    definition: definition.range,
                    id,
                });
                return;
            }
        }
    }

    fn visit_string(&mut self, string: &AstString, ast: &Ast) {
        if let StringContents::Interpolated(string_nodes) = &string.contents {
            for string_node in string_nodes.iter() {
                if let StringNode::Expression { expression, .. } = string_node {
                    self.visit_node(*expression, ast, false);
                };
            }
        }
    }
}

#[derive(Default)]
struct Frame {
    definitions: Vec<Definition>,
}

impl Frame {
    fn with_capacity(local_count: usize) -> Self {
        Self {
            definitions: Vec::with_capacity(local_count),
        }
    }

    fn add_definition(&mut self, id: ConstantIndex, span: Span) {
        self.definitions.push(Definition {
            range: koto_span_to_lsp_range(span),
            id,
        })
    }

    fn get_definition(&self, id: ConstantIndex) -> Option<&Definition> {
        self.definitions
            .iter()
            .find(|definition| definition.id == id)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Definition {
    range: Range,
    id: ConstantIndex,
}

#[cfg(test)]
mod test {
    use super::*;
    use koto::parser::Parser;
    use tower_lsp::lsp_types::Position;

    fn position(line: u32, character: u32) -> Position {
        Position { line, character }
    }

    fn range(line: u32, column: u32, length: u32) -> Range {
        Range {
            start: position(line, column),
            end: position(line, column + length),
        }
    }

    fn reference(
        reference_range: (u32, u32, u32),
        definition: (u32, u32, u32),
        id: ConstantIndex,
    ) -> Reference {
        Reference {
            range: range(reference_range.0, reference_range.1, reference_range.2),
            definition: range(definition.0, definition.1, definition.2),
            id,
        }
    }

    mod from_ast {
        use super::*;

        fn from_ast_test(script: &str, expected: SourceInfo) -> Result<()> {
            let ast = Parser::parse(script)?;
            let result = SourceInfo::from_ast(&ast);

            for (i, (expected, actual)) in expected
                .references
                .iter()
                .zip(result.references.iter())
                .enumerate()
            {
                assert_eq!(expected, actual, "mismatch in reference {i}");
            }
            assert_eq!(expected.references.len(), result.references.len());

            Ok(())
        }

        fn source_info(references: &[Reference]) -> SourceInfo {
            SourceInfo {
                references: references.to_vec(),
            }
        }

        #[test]
        fn empty_script() -> Result<()> {
            from_ast_test("", source_info(&[]))
        }

        #[test]
        fn single_assignment() -> Result<()> {
            let script = "x = 1";
            from_ast_test(script, source_info(&[]))
        }

        #[test]
        fn single_reference() -> Result<()> {
            let script = "\
x = 1
10 * x
";
            from_ast_test(script, source_info(&[reference((1, 5, 1), (0, 0, 1), 0)]))
        }

        #[test]
        fn multiple_references() -> Result<()> {
            let script = "\
a, b = 1, 2
a + b
";
            from_ast_test(
                script,
                source_info(&[
                    reference((1, 0, 1), (0, 0, 1), 0), // a
                    reference((1, 4, 1), (0, 3, 1), 1), // b
                ]),
            )
        }

        #[test]
        fn function_with_capture() -> Result<()> {
            let script = "\
foo = 42
|bar|
  99 + 100
  bar + foo
";
            from_ast_test(
                script,
                source_info(&[
                    reference((3, 2, 3), (1, 1, 3), 1), // bar
                    reference((3, 8, 3), (0, 0, 3), 0), // foo
                ]),
            )
        }
    }

    mod get_reference {
        use super::*;

        fn get_reference_test(script: &str, cases: &[(Position, Option<Range>)]) -> Result<()> {
            let ast = Parser::parse(script)?;
            let info = SourceInfo::from_ast(&ast);

            for (i, (position, expected)) in cases.iter().enumerate() {
                let result = info.get_reference(*position);
                match (expected, result) {
                    (Some(expected), Some(result)) => {
                        assert_eq!(*expected, result.definition, "mismatch in case {i}");
                    }
                    (None, None) => {}
                    _ => panic!(
                        "mismatch in case {i}: expected: {:?}, actual: {:?}",
                        expected, result
                    ),
                }
            }

            Ok(())
        }

        #[test]
        fn single_assignment() -> Result<()> {
            let script = "\
x = 42
1 + x
";
            get_reference_test(
                script,
                &[
                    (position(1, 4), Some(range(0, 0, 1))),
                    (position(1, 3), None),
                ],
            )
        }

        #[test]
        fn multi_assignment() -> Result<()> {
            let script = "\
a, b, c = 1, 2, 3
a + b + c
";
            get_reference_test(
                script,
                &[
                    (position(1, 0), Some(range(0, 0, 1))),
                    (position(1, 4), Some(range(0, 3, 1))),
                    (position(1, 8), Some(range(0, 6, 1))),
                    (position(1, 2), None),
                ],
            )
        }
    }
}
