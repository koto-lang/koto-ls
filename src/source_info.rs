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
    // A vec of all definitions, sorted by start position
    definitions: Vec<Definition>,
    // A vec of all references, sorted by start position
    references: Vec<Reference>,
}

impl SourceInfo {
    pub fn from_ast(ast: &Ast) -> Self {
        SourceInfoBuilder::from_ast(ast).build()
    }

    pub fn get_reference(&self, position: Position) -> Option<&Reference> {
        if let Ok(i) = self
            .references
            .binary_search_by(|reference| cmp_position_to_range(position, &reference.range))
        {
            Some(&self.references[i])
        } else {
            None
        }
    }

    pub fn find_references(
        &self,
        position: Position,
        include_definition: bool,
    ) -> Option<FindReferencesIter> {
        self.definitions
            // Find the definition at the given position
            .binary_search_by(|definition| cmp_position_to_range(position, &definition.range))
            .ok()
            .map(|i| self.definitions[i].range)
            // If no definition was found, what about a reference?
            .or_else(|| {
                self.get_reference(position)
                    .map(|reference| reference.definition)
            })
            // Make an output iterator if a definition has been found
            .map(|definition| FindReferencesIter {
                definition,
                references: self.references.iter(),
                include_definition,
            })
    }
}

#[derive(Clone)]
pub struct FindReferencesIter<'a> {
    definition: Range,
    references: std::slice::Iter<'a, Reference>,
    include_definition: bool,
}

impl<'a> Iterator for FindReferencesIter<'a> {
    type Item = Range;

    fn next(&mut self) -> Option<Self::Item> {
        if self.include_definition {
            self.include_definition = false;
            Some(self.definition)
        } else {
            for reference in self.references.by_ref() {
                if reference.definition == self.definition {
                    return Some(reference.range);
                }
            }
            None
        }
    }
}

fn cmp_position_to_range(position: Position, range: &Range) -> Ordering {
    if position < range.start {
        Ordering::Greater
    } else if position >= range.end {
        Ordering::Less
    } else {
        Ordering::Equal
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Definition {
    range: Range,
    id: ConstantIndex,
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
    definitions: Vec<Definition>,
    references: Vec<Reference>,
}

impl SourceInfoBuilder {
    fn from_ast(ast: &Ast) -> Self {
        let mut result = Self::default();

        if let Some(entry_point) = ast.entry_point() {
            result.visit_node(entry_point, ast, false);
        };

        result
    }

    fn build(mut self) -> SourceInfo {
        // Sort the definitions, they get added in pop_frame so they aren't in order
        self.definitions
            .sort_by_key(|definition| definition.range.start);
        // References are already sorted
        debug_assert!(is_sorted::IsSorted::is_sorted_by_key(
            &mut self.references.iter(),
            |reference| reference.range.start
        ));
        SourceInfo {
            definitions: self.definitions,
            references: self.references,
        }
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
                self.push_frame(*local_count);
                self.visit_nested(body, ast, false);
                self.pop_frame();
            }
            Node::Function(info) => {
                self.push_frame(info.local_count + info.args.len());
                self.visit_nested(&info.args, ast, true);
                self.visit_node(info.body, ast, false);
                self.pop_frame();
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
                // Visit the RHS first to find rhs references before redefinitions,
                // e.g.
                // n = 1
                // n = n + n
                self.visit_node(*expression, ast, false);
                self.visit_node(*target, ast, true);
            }
            Node::MultiAssign {
                targets,
                expression,
            } => {
                self.visit_node(*expression, ast, false);
                self.visit_nested(targets, ast, true);
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

    fn push_frame(&mut self, locals_capacity: usize) {
        self.frames.push(Frame::with_capacity(locals_capacity));
    }

    fn pop_frame(&mut self) {
        let frame = self.frames.pop().expect("Missing frame");
        self.definitions.extend(frame.definitions);
    }
}

#[derive(Default, Debug)]
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
            .rev() // reversed so that the most recent matching definition is found
            .find(|definition| definition.id == id)
    }
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

    mod find_references {
        use super::*;

        fn find_references_test(
            script: &str,
            cases: &[(Position, Option<&[Range]>, bool)],
        ) -> Result<()> {
            let ast = Parser::parse(script)?;
            let info = SourceInfo::from_ast(&ast);

            for (i, (position, expected_references, include_definition)) in cases.iter().enumerate()
            {
                let references = info.find_references(*position, *include_definition);

                match (expected_references, references) {
                    (Some(expected_references), Some(mut references)) => {
                        for (j, (expected, actual)) in expected_references
                            .iter()
                            .zip(references.clone())
                            .enumerate()
                        {
                            assert_eq!(*expected, actual, "mismatch in case {i}, reference {j}");
                        }

                        assert_eq!(
                            expected_references.len(),
                            references.count(),
                            "reference count mismatch in case {i}"
                        );
                    }
                    (None, None) => {}
                    (Some(_), None) => {
                        panic!("mismatch in case {i} - expected references but none were found")
                    }
                    (None, Some(_)) => {
                        panic!("mismatch in case {i} - expected no references but some were found")
                    }
                }
            }

            Ok(())
        }

        #[test]
        fn single_assignment() -> Result<()> {
            let script = "\
x = 42
1 + x
  + x
";
            find_references_test(
                script,
                &[
                    (
                        position(0, 0),
                        Some(&[range(1, 4, 1), range(2, 4, 1)]),
                        false,
                    ),
                    (
                        position(0, 0),
                        Some(&[range(0, 0, 1), range(1, 4, 1), range(2, 4, 1)]),
                        true,
                    ),
                    (
                        position(1, 4),
                        Some(&[range(0, 0, 1), range(1, 4, 1), range(2, 4, 1)]),
                        true,
                    ),
                    (
                        position(2, 4),
                        Some(&[range(1, 4, 1), range(2, 4, 1)]),
                        false,
                    ),
                ],
            )
        }

        #[test]
        fn multiple_assignments() -> Result<()> {
            let script = "\
a, b, c = 1, 2, 3
a
b
c
a + a
b + b
c + c
";
            find_references_test(
                script,
                &[
                    (
                        position(4, 4), // a
                        Some(&[
                            range(0, 0, 1),
                            range(1, 0, 1),
                            range(4, 0, 1),
                            range(4, 4, 1),
                        ]),
                        true,
                    ),
                    (
                        position(2, 0), // b
                        Some(&[range(2, 0, 1), range(5, 0, 1), range(5, 4, 1)]),
                        false,
                    ),
                    (
                        position(6, 0), // c
                        Some(&[
                            range(0, 6, 1),
                            range(3, 0, 1),
                            range(6, 0, 1),
                            range(6, 4, 1),
                        ]),
                        true,
                    ),
                ],
            )
        }

        #[test]
        fn definition_after_function() -> Result<()> {
            let script = "\
foo = 1, 2, 3
bar = |n|
  n * size foo
x = foo
";
            find_references_test(
                script,
                &[
                    (
                        position(0, 0), // foo
                        Some(&[range(0, 0, 3), range(2, 11, 3), range(3, 4, 3)]),
                        true,
                    ),
                    (
                        position(2, 2), // n
                        Some(&[range(1, 7, 1), range(2, 2, 1)]),
                        true,
                    ),
                ],
            )
        }

        #[test]
        fn redefinition_in_function() -> Result<()> {
            let script = "\
foo = |n|
  n = n.floor()
  n * n
";
            find_references_test(
                script,
                &[
                    (
                        position(0, 7), // n - arg
                        Some(&[range(0, 7, 1), range(1, 6, 1)]),
                        true,
                    ),
                    (
                        position(2, 2), // n - redefinition
                        Some(&[range(1, 2, 1), range(2, 2, 1), range(2, 6, 1)]),
                        true,
                    ),
                ],
            )
        }
    }
}
