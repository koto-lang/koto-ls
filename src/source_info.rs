use koto::parser::{
    Ast, AstIndex, AstNode, AstString, ChainNode, ConstantIndex, ImportItem, Node, Span,
    StringContents, StringNode, StringSlice,
};
use std::{cmp::Ordering, sync::Arc};
use tower_lsp::lsp_types::{DocumentSymbol, Position, Range, SymbolKind, Url};

use crate::utils::koto_span_to_lsp_range;

#[derive(Clone, Debug, PartialEq)]
pub struct SourceInfo {
    // A vec of all definitions, sorted by start position
    definitions: Vec<Definition>,
    // A vec of all references, sorted by start position
    references: Vec<Reference>,
}

impl SourceInfo {
    pub fn from_ast(ast: &Ast, uri: Arc<Url>) -> Self {
        SourceInfoBuilder::from_ast(ast, uri).build()
    }

    pub fn get_definition_location(
        &self,
        position: Position,
        include_references: bool,
    ) -> Option<Location> {
        self.definitions
            .binary_search_by(|definition| {
                cmp_position_to_range(position, &definition.location.range)
            })
            .ok()
            .map(|i| self.definitions[i].location.clone())
            .or_else(|| {
                if include_references {
                    self.references
                        .binary_search_by(|reference| {
                            cmp_position_to_range(position, &reference.location.range)
                        })
                        .ok()
                        .map(|i| self.references[i].definition.clone())
                } else {
                    None
                }
            })
    }

    pub fn find_references(
        &self,
        position: Position,
        include_definition: bool,
    ) -> Option<FindReferencesIter> {
        self.get_definition_location(position, true)
            .map(|definition| FindReferencesIter {
                definition,
                references: self.references.iter(),
                include_definition,
            })
    }

    pub fn top_level_definitions(&self) -> impl Iterator<Item = &Definition> {
        self.definitions
            .iter()
            .filter(|definition| definition.top_level)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Location {
    pub uri: Arc<Url>,
    pub range: Range,
}

impl Location {
    fn new(uri: Arc<Url>, span: Span) -> Self {
        Self {
            uri,
            range: koto_span_to_lsp_range(span),
        }
    }
}

impl From<Location> for tower_lsp::lsp_types::Location {
    fn from(value: Location) -> Self {
        Self {
            uri: value.uri.as_ref().clone(),
            range: value.range,
        }
    }
}

#[derive(Clone)]
pub struct FindReferencesIter<'a> {
    definition: Location,
    references: std::slice::Iter<'a, Reference>,
    include_definition: bool,
}

impl<'a> Iterator for FindReferencesIter<'a> {
    type Item = Location;

    fn next(&mut self) -> Option<Self::Item> {
        if self.include_definition {
            self.include_definition = false;
            Some(self.definition.clone())
        } else {
            for reference in self.references.by_ref() {
                if reference.definition == self.definition {
                    return Some(reference.location.clone());
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
    location: Location,
    id: StringSlice,
    kind: SymbolKind,
    // true for definitions at the top-level of the script, i.e. not in a function
    top_level: bool,
    children: Option<Vec<Definition>>,
}

impl Definition {
    fn new(
        id: StringSlice,
        location: Location,
        kind: SymbolKind,
        top_level: bool,
        children: Vec<Definition>,
    ) -> Self {
        Self {
            location,
            id,
            kind,
            top_level,
            children: if children.is_empty() {
                None
            } else {
                Some(children)
            },
        }
    }
}

impl From<&Definition> for DocumentSymbol {
    fn from(definition: &Definition) -> Self {
        let children = definition
            .children
            .as_ref()
            .map(|children| children.iter().map(DocumentSymbol::from).collect());

        #[allow(deprecated)]
        Self {
            name: definition.id.as_str().into(),
            detail: None,
            kind: definition.kind,
            tags: None,
            deprecated: None,
            range: definition.location.range,
            selection_range: definition.location.range,
            children,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Reference {
    pub location: Location,
    pub definition: Location,
    pub id: StringSlice,
}

struct SourceInfoBuilder {
    // The uri of the file that is being scanned
    uri: Arc<Url>,
    // A stack of frames, each time a function is encountered a new frame is added to the stack
    frames: Vec<Frame>,
    // All definitions that have been found in the file.
    //
    // Definitions are collected in frames and then appended to this vec when the frame is popped
    // off the stack. This results in an unsorted ordering, so the definitions get sorted in the
    // build function.
    definitions: Vec<Definition>,
    // All references that have been found in the file.
    // The references get added as soon as they're encountered in the AST, so they're always sorted.
    references: Vec<Reference>,
}

impl SourceInfoBuilder {
    fn from_ast(ast: &Ast, uri: Arc<Url>) -> Self {
        let mut result = Self {
            uri,
            frames: Vec::new(),
            definitions: Vec::new(),
            references: Vec::new(),
        };

        if let Some(entry_point) = ast.entry_point() {
            result.visit_node(entry_point, Context::new(ast));
        };

        result
    }

    fn build(mut self) -> SourceInfo {
        // Sort the definitions, they get added in pop_frame so they aren't in order
        self.definitions
            .sort_by_key(|definition| definition.location.range.start);

        // References should already be sorted
        debug_assert!(is_sorted::IsSorted::is_sorted_by_key(
            &mut self.references.iter(),
            |reference| reference.location.range.start
        ));

        SourceInfo {
            definitions: self.definitions,
            references: self.references,
        }
    }

    // Returns an optional list of child definitions
    fn visit_node(&mut self, node_index: AstIndex, ctx: Context) -> Vec<Definition> {
        let mut child_definitions = Vec::new();

        let node = ctx.node(node_index);
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
            } => {
                self.visit_node(*node, ctx.default());
            }
            // Nodes with a list of nodes that should be visited
            Node::List(nodes)
            | Node::Tuple(nodes)
            | Node::TempTuple(nodes)
            | Node::Block(nodes) => self.visit_nested(nodes, ctx.default()),
            // Nodes with an optional child node
            Node::Break(maybe_node) | Node::Return(maybe_node) => {
                if let Some(node) = maybe_node {
                    self.visit_node(*node, ctx.default());
                }
            }
            Node::Id(id) => {
                if ctx.id_is_definition {
                    self.add_definition(
                        ctx.string(*id),
                        SymbolKind::VARIABLE,
                        vec![],
                        node,
                        ctx.ast,
                    );
                } else {
                    self.add_reference(*id, node, ctx.ast);
                }
            }
            Node::Meta(_, _) => {
                // There may be something to do here with named meta entries?
            }
            Node::Chain((chain_node, next)) => self.visit_chain(node, chain_node, next, &ctx),
            Node::Str(s) => self.visit_string(s, ctx.default()),
            Node::Range { start, end, .. } => {
                self.visit_node(*start, ctx.default());
                self.visit_node(*end, ctx.default());
            }
            Node::Map(entries) => child_definitions = self.visit_map(entries, &ctx),
            Node::MainBlock { body, local_count } => {
                self.push_frame(*local_count);
                self.visit_nested(body, ctx.default());
                self.pop_frame();
            }
            Node::Function(info) => {
                self.push_frame(info.local_count + info.args.len());
                self.visit_nested(&info.args, ctx.with_ids_as_definitions());
                self.visit_node(info.body, ctx.default());
                self.pop_frame();
            }
            Node::Import { from, items } => self.visit_import(from, items, &ctx),
            Node::Export(item) => {
                // Set id_is_definition to true to count exported map keys as definitions
                self.visit_node(*item, ctx.with_ids_as_definitions());
            }
            Node::Assign { target, expression } => self.visit_assign(*target, *expression, &ctx),
            Node::MultiAssign {
                targets,
                expression,
            } => {
                self.visit_node(*expression, ctx.default());
                self.visit_nested(targets, ctx.with_ids_as_definitions());
            }
            Node::BinaryOp { lhs, rhs, .. } => {
                self.visit_node(*lhs, ctx.default());
                self.visit_node(*rhs, ctx.default());
            }
            Node::If(info) => {
                self.visit_node(info.condition, ctx.default());
                self.visit_node(info.then_node, ctx.default());
                for (else_if_condition, else_if_block) in info.else_if_blocks.iter() {
                    self.visit_node(*else_if_condition, ctx.default());
                    self.visit_node(*else_if_block, ctx.default());
                }
                if let Some(else_node) = info.else_node {
                    self.visit_node(else_node, ctx.default());
                }
            }
            Node::Match { expression, arms } => {
                self.visit_node(*expression, ctx.default());
                for arm in arms.iter() {
                    for pattern in arm.patterns.iter() {
                        self.visit_node(*pattern, ctx.with_ids_as_definitions());
                    }
                    if let Some(condition) = arm.condition {
                        self.visit_node(condition, ctx.default());
                    }
                    self.visit_node(arm.expression, ctx.default());
                }
            }
            Node::Switch(arms) => {
                for arm in arms.iter() {
                    if let Some(condition) = arm.condition {
                        self.visit_node(condition, ctx.default());
                    }
                    self.visit_node(arm.expression, ctx.default());
                }
            }
            Node::Ellipsis(maybe_id) => {
                if let Some(id) = maybe_id {
                    if ctx.id_is_definition {
                        self.add_definition(
                            ctx.string(*id),
                            SymbolKind::VARIABLE,
                            vec![],
                            node,
                            ctx.ast,
                        );
                    }
                }
            }
            Node::For(info) => {
                self.visit_nested(&info.args, ctx.with_ids_as_definitions());
                self.visit_node(info.iterable, ctx.default());
                self.visit_node(info.body, ctx.default());
            }
            Node::While { condition, body } | Node::Until { condition, body } => {
                self.visit_node(*condition, ctx.default());
                self.visit_node(*body, ctx.default());
            }
            Node::Try(info) => {
                self.visit_node(info.try_block, ctx.default());
                self.visit_node(info.catch_arg, ctx.with_ids_as_definitions());
                self.visit_node(info.catch_block, ctx.default());
                if let Some(finally_block) = info.finally_block {
                    self.visit_node(finally_block, ctx.default());
                }
            }
        };

        child_definitions
    }

    fn visit_nested(&mut self, nested: &[AstIndex], ctx: Context) {
        for node in nested.iter() {
            self.visit_node(*node, ctx.clone());
        }
    }

    fn visit_map(
        &mut self,
        entries: &[(AstIndex, Option<AstIndex>)],
        ctx: &Context,
    ) -> Vec<Definition> {
        let mut child_definitions = Vec::new();

        for (key, value) in entries.iter() {
            let key_node = ctx.node(*key);
            match &key_node.node {
                Node::Str(s) => self.visit_string(s, ctx.default()),
                Node::Id(id) => {
                    // Shorthand syntax?
                    if value.is_none() {
                        self.add_reference(*id, key_node, ctx.ast);
                    }

                    // Count the map key as a top-level definition?
                    // id_is_definition will be true when exporting a map.
                    if ctx.id_is_definition {
                        self.add_definition(
                            ctx.string(*id),
                            SymbolKind::FIELD,
                            vec![],
                            key_node,
                            ctx.ast,
                        );
                    } else {
                        child_definitions.push(Definition::new(
                            ctx.string(*id),
                            Location::new(self.uri.clone(), *ctx.ast.span(key_node.span)),
                            SymbolKind::FIELD,
                            self.frames.len() == 1, // TODO - use frame.is_top_level?
                            vec![],                 // TODO - nested child definitions?
                        ))
                    }
                }
                Node::Meta(key_id, maybe_name) => {
                    let field_id = match maybe_name {
                        Some(name) => format!("{key_id} {}", ctx.string(*name).as_str()),
                        None => format!("{key_id}"),
                    };
                    child_definitions.push(Definition::new(
                        StringSlice::from(field_id),
                        Location::new(self.uri.clone(), *ctx.ast.span(key_node.span)),
                        SymbolKind::FIELD,
                        self.frames.len() == 1, // TODO - use frame.is_top_level?
                        vec![],                 // TODO - nested child definitions?
                    ))
                }
                _ => {}
            }
            if let Some(value) = value {
                self.visit_node(*value, ctx.default());
            }
        }

        child_definitions
    }

    fn visit_import(&mut self, from: &[AstIndex], items: &[ImportItem], ctx: &Context) {
        for (i, source) in from.iter().enumerate() {
            let source_node = ctx.node(*source);
            match &source_node.node {
                Node::Id(id) => {
                    if i == 0 {
                        self.add_reference(*id, source_node, ctx.ast);
                    }
                }
                Node::Str(s) => self.visit_string(s, ctx.default()),
                _ => {}
            }
        }
        for item in items.iter() {
            let item_node = ctx.node(item.item);
            match (&item_node.node, item.name) {
                (Node::Id(id), None) => self.add_definition(
                    ctx.string(*id),
                    SymbolKind::VARIABLE,
                    vec![],
                    item_node,
                    ctx.ast,
                ),
                (Node::Str(s), None) => self.visit_string(s, ctx.default()),
                (_, Some(name)) => {
                    let name_node = ctx.node(name);
                    if let Node::Id(id) = &name_node.node {
                        self.add_definition(
                            ctx.string(*id),
                            SymbolKind::VARIABLE,
                            vec![],
                            name_node,
                            ctx.ast,
                        )
                    }
                }
                _ => {}
            }
        }
    }

    fn visit_assign(&mut self, target: AstIndex, expression: AstIndex, ctx: &Context) {
        let target_node = ctx.node(target);
        match &target_node.node {
            Node::Id(id) => {
                // LHS is an id, so this is a definition
                let kind = node_symbol_kind(&ctx.node(expression).node);

                // Visit the RHS before adding the definition to find rhs references before
                // redefinitions, e.g.
                //   n = 1
                //   n = n + n
                let child_definitions = self.visit_node(expression, ctx.default());
                self.add_definition(
                    ctx.string(*id),
                    kind,
                    child_definitions,
                    target_node,
                    ctx.ast,
                );
            }
            Node::Meta(key_id, maybe_name) => {
                let child_definitions = self.visit_node(expression, ctx.default());
                let target_id = match maybe_name {
                    Some(name) => format!("{key_id} {}", ctx.string(*name).as_str()),
                    None => format!("{key_id}"),
                };
                self.add_definition(
                    StringSlice::from(target_id),
                    SymbolKind::FIELD,
                    child_definitions,
                    target_node,
                    ctx.ast,
                );
            }
            _ => {
                // Visit the LHS first to keep references in order
                self.visit_node(target, ctx.default());
                self.visit_node(expression, ctx.default());
            }
        }
    }

    fn visit_chain(
        &mut self,
        node: &AstNode,
        chain_node: &ChainNode,
        next: &Option<AstIndex>,
        ctx: &Context,
    ) {
        match chain_node {
            ChainNode::Root(root) => {
                self.visit_node(*root, ctx.default());
            }
            ChainNode::Id(id) => self.add_reference(*id, node, ctx.ast),
            ChainNode::Str(s) => self.visit_string(s, ctx.default()),
            ChainNode::Index(node) => {
                self.visit_node(*node, ctx.default());
            }
            ChainNode::Call { args, .. } => self.visit_nested(args, ctx.default()),
        }
        if let Some(next) = next {
            self.visit_node(*next, ctx.default());
        }
    }

    fn visit_string(&mut self, string: &AstString, ctx: Context) {
        if let StringContents::Interpolated(string_nodes) = &string.contents {
            for string_node in string_nodes.iter() {
                if let StringNode::Expression { expression, .. } = string_node {
                    self.visit_node(*expression, ctx.default());
                };
            }
        }
    }

    fn add_definition(
        &mut self,
        id: StringSlice,
        kind: SymbolKind,
        children: Vec<Definition>,
        node: &AstNode,
        ast: &Ast,
    ) {
        let span = ast.span(node.span);
        self.frames
            .last_mut()
            .expect("Missing frame")
            .add_definition(id, Location::new(self.uri.clone(), *span), kind, children);
    }

    fn add_reference(&mut self, id: ConstantIndex, node: &AstNode, ast: &Ast) {
        let id = ast.constants().get_string_slice(id);
        for frame in self.frames.iter().rev() {
            if let Some(definition) = frame.get_definition(&id) {
                let span = ast.span(node.span);
                self.references.push(Reference {
                    location: Location::new(self.uri.clone(), *span),
                    definition: definition.location.clone(),
                    id,
                });
                return;
            }
        }
    }

    fn push_frame(&mut self, locals_capacity: usize) {
        self.frames.push(Frame {
            definitions: Vec::with_capacity(locals_capacity),
            top_level: self.frames.is_empty(),
        });
    }

    fn pop_frame(&mut self) {
        let frame = self.frames.pop().expect("Missing frame");
        self.definitions.extend(frame.definitions);
    }
}

#[derive(Default, Debug)]
struct Frame {
    definitions: Vec<Definition>,
    top_level: bool,
}

impl Frame {
    fn add_definition(
        &mut self,
        id: StringSlice,
        location: Location,
        kind: SymbolKind,
        children: Vec<Definition>,
    ) {
        self.definitions.push(Definition::new(
            id,
            location,
            kind,
            self.top_level,
            children,
        ));
    }

    fn get_definition(&self, id: &StringSlice) -> Option<&Definition> {
        self.definitions
            .iter()
            .rev() // reversed so that the most recent matching definition is found
            .find(|definition| definition.id == *id)
    }
}

#[derive(Clone)]
struct Context<'a> {
    ast: &'a Ast,
    id_is_definition: bool,
}

impl<'a> Context<'a> {
    fn new(ast: &'a Ast) -> Self {
        Self {
            ast,
            id_is_definition: false,
        }
    }

    fn default(&self) -> Self {
        Self {
            ast: self.ast,
            id_is_definition: false,
        }
    }

    fn with_ids_as_definitions(&self) -> Self {
        Self {
            ast: self.ast,
            id_is_definition: true,
        }
    }

    fn node(&self, index: AstIndex) -> &AstNode {
        self.ast.node(index)
    }

    fn string(&self, constant_index: ConstantIndex) -> StringSlice {
        self.ast.constants().get_string_slice(constant_index)
    }
}

fn node_symbol_kind(node: &Node) -> SymbolKind {
    use Node::*;

    match node {
        Null => SymbolKind::NULL,
        BoolTrue | BoolFalse => SymbolKind::BOOLEAN,
        SmallInt { .. } | Int { .. } | Float { .. } => SymbolKind::NUMBER,
        Str { .. } => SymbolKind::STRING,
        List { .. } | Tuple { .. } | TempTuple { .. } => SymbolKind::ARRAY,
        Map { .. } => SymbolKind::OBJECT,
        Function { .. } => SymbolKind::FUNCTION,
        _ => SymbolKind::VARIABLE,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;
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

    fn test_uri() -> Arc<Url> {
        Arc::new(Url::parse("file:///test.koto").unwrap())
    }

    mod goto_definition {
        use super::*;

        fn goto_definition_test(script: &str, cases: &[(Position, Option<Range>)]) -> Result<()> {
            let ast = Parser::parse(script)?;
            let info = SourceInfo::from_ast(&ast, test_uri());

            for (i, (position, expected)) in cases.iter().enumerate() {
                let result = info.get_definition_location(*position, true);
                match (expected, &result) {
                    (Some(expected), Some(result)) => {
                        assert_eq!(*expected, result.range, "mismatch in case {i}");
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
            goto_definition_test(
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
            goto_definition_test(
                script,
                &[
                    (position(1, 0), Some(range(0, 0, 1))),
                    (position(1, 4), Some(range(0, 3, 1))),
                    (position(1, 8), Some(range(0, 6, 1))),
                    (position(1, 2), None),
                ],
            )
        }

        #[test]
        fn call_arg() -> Result<()> {
            let script = "\
f = |x| x * x
a = 42
f a
";
            goto_definition_test(
                script,
                &[
                    (position(2, 0), Some(range(0, 0, 1))), // f
                    (position(2, 2), Some(range(1, 0, 1))), // a
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
            let info = SourceInfo::from_ast(&ast, test_uri());

            for (i, (position, expected_references, include_definition)) in cases.iter().enumerate()
            {
                let references = info.find_references(*position, *include_definition);

                match (expected_references, references) {
                    (Some(expected_references), Some(references)) => {
                        for (j, (expected, actual)) in expected_references
                            .iter()
                            .zip(references.clone())
                            .enumerate()
                        {
                            assert_eq!(
                                *expected, actual.range,
                                "mismatch in case {i}, reference {j}"
                            );
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

        #[test]
        fn map_shorthand() -> Result<()> {
            let script = "\
foo = 99
{bar: foo, foo}
";
            find_references_test(
                script,
                &[(
                    position(0, 0), // foo
                    Some(&[range(0, 0, 3), range(1, 6, 3), range(1, 11, 3)]),
                    true,
                )],
            )
        }

        #[test]
        fn imported_item() -> Result<()> {
            let script = "\
import foo, bar as baz
foo()
from baz import foo
";
            find_references_test(
                script,
                &[
                    (
                        position(1, 0), // foo
                        Some(&[range(0, 7, 3), range(1, 0, 3)]),
                        true,
                    ),
                    (
                        position(2, 6), // baz
                        Some(&[range(0, 19, 3), range(2, 5, 3)]),
                        true,
                    ),
                ],
            )
        }

        #[test]
        fn capture_of_imported_item() -> Result<()> {
            let script = "\
from foo import bar
x = |y| y.baz = bar
";
            find_references_test(
                script,
                &[(
                    position(0, 17), // bar
                    Some(&[range(0, 16, 3), range(1, 16, 3)]),
                    true,
                )],
            )
        }
    }

    mod top_level_definitions {
        use tower_lsp::lsp_types::SymbolKind;

        use super::*;

        struct TestDefinition<'a> {
            range: Range,
            id: &'static str,
            kind: SymbolKind,
            children: &'a [TestDefinition<'a>],
        }

        fn definition<'a>(
            range: Range,
            id: &'static str,
            kind: SymbolKind,
            children: &'a [TestDefinition<'a>],
        ) -> TestDefinition<'a> {
            TestDefinition {
                range,
                id,
                kind,
                children,
            }
        }

        fn top_level_definitions_test(
            script: &str,
            expected_definitions: &[TestDefinition],
        ) -> Result<()> {
            let ast = Parser::parse(script)?;
            let info = SourceInfo::from_ast(&ast, test_uri());
            let definitions = info.top_level_definitions().collect::<Vec<_>>();

            for (i, (expected, actual)) in expected_definitions
                .iter()
                .zip(definitions.iter())
                .enumerate()
            {
                assert_eq!(
                    expected.range, actual.location.range,
                    "mismatch in definition {i}"
                );
                assert_eq!(
                    expected.id,
                    actual.id.as_str(),
                    "mismatch in definition {i}"
                );
                assert_eq!(expected.kind, actual.kind, "mismatch in definition {i}");

                if let Some(actual_children) = &actual.children {
                    for (j, (expected_child, actual_child)) in expected
                        .children
                        .iter()
                        .zip(actual_children.iter())
                        .enumerate()
                    {
                        assert_eq!(
                            expected_child.range, actual_child.location.range,
                            "mismatch in definition {i}, child {j}"
                        );
                        assert_eq!(
                            expected_child.id,
                            actual_child.id.as_str(),
                            "mismatch in definition {i}, child {j}"
                        );
                        assert_eq!(
                            expected_child.kind, actual_child.kind,
                            "mismatch in definition {i}, child {j}"
                        );
                    }

                    assert_eq!(
                        expected.children.len(),
                        actual_children.len(),
                        "child count mismatch in definition {i}"
                    );
                } else {
                    assert!(expected.children.is_empty(), "mismatch in definition {i}");
                }
            }

            assert_eq!(
                expected_definitions.len(),
                definitions.len(),
                "definition count mismatch"
            );

            Ok(())
        }

        #[test]
        fn top_level_assignments() -> Result<()> {
            let script = "\
a = 42
foo = 99

bar = |n|
  x = n
  x * x

x, y, z = f()
";
            top_level_definitions_test(
                script,
                &[
                    definition(range(0, 0, 1), "a", SymbolKind::NUMBER, &[]),
                    definition(range(1, 0, 3), "foo", SymbolKind::NUMBER, &[]),
                    definition(range(3, 0, 3), "bar", SymbolKind::FUNCTION, &[]),
                    definition(range(7, 0, 1), "x", SymbolKind::VARIABLE, &[]),
                    definition(range(7, 3, 1), "y", SymbolKind::VARIABLE, &[]),
                    definition(range(7, 6, 1), "z", SymbolKind::VARIABLE, &[]),
                ],
            )
        }

        #[test]
        fn exported_map_keys() -> Result<()> {
            let script = "\
export
  a: 123
  b: 99
";
            top_level_definitions_test(
                script,
                &[
                    definition(range(1, 2, 1), "a", SymbolKind::FIELD, &[]),
                    definition(range(2, 2, 1), "b", SymbolKind::FIELD, &[]),
                ],
            )
        }

        #[test]
        fn map_entries() -> Result<()> {
            let script = "\
x = 
  a: 123
  b: 99
";
            top_level_definitions_test(
                script,
                &[definition(
                    range(0, 0, 1),
                    "x",
                    SymbolKind::OBJECT,
                    &[
                        definition(range(1, 2, 1), "a", SymbolKind::FIELD, &[]),
                        definition(range(2, 2, 1), "b", SymbolKind::FIELD, &[]),
                    ],
                )],
            )
        }
    }
}
