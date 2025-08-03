use koto_bytecode::Compiler;
use koto_parser::{
    Ast, AstIndex, AstNode, AstString, ChainNode, ConstantIndex, ImportItem, Node, Parser, Span,
    StringContents, StringNode, StringSlice,
};
use std::{cmp::Ordering, fs, sync::Arc};
use thiserror::Error;
use tower_lsp_server::{
    UriExt,
    lsp_types::{DocumentSymbol, Position, Range, SymbolKind, Uri},
};

use crate::{
    info_cache::InfoCache,
    utils::{default, koto_span_to_lsp_range},
};

/// Errors that could occur while analyzing a source file
#[derive(Error, Clone, Debug)]
pub enum Error {
    #[error(transparent)]
    Parser(#[from] koto_parser::Error),
    #[error(transparent)]
    Compiler(#[from] koto_bytecode::CompilerError),
}

impl Error {
    pub fn span(&self) -> Option<Span> {
        match self {
            Error::Parser(e) => Some(e.span),
            Error::Compiler(e) => Some(e.span),
        }
    }
}

/// Analyzed information about the contents of a source file
#[derive(Clone, Debug, Default)]
pub struct SourceInfo {
    // The source file's contents
    source: String,
    // A vec of all definitions, sorted by start position
    definitions: Vec<Definition>,
    // A vec of all references, sorted by start position
    references: Vec<Reference>,
    // A vec of all scopes, sorted by start position
    scopes: Vec<ScopeInfo>,
    /// If an error was encountered while compiling the script it's cached here
    pub error: Option<Error>,
}

/// Information about a scope (function, block, etc.)
#[derive(Clone, Debug, PartialEq)]
pub struct ScopeInfo {
    pub range: Range,
    pub kind: ScopeKind,
    pub parent_scope: Option<usize>, // Index into scopes vec
}

#[derive(Clone, Debug, PartialEq)]
pub enum ScopeKind {
    Global,
    Function,
    Block,
}

impl SourceInfo {
    /// Returns a [SourceInfo] containing the result of analyzing the given script
    pub fn new(script: String, uri: Arc<Uri>, info_cache: &mut InfoCache) -> Self {
        let mut error = None;
        let ast = match Parser::parse(&script) {
            Ok(ast) => ast,
            Err(mut parse_error) => {
                if let Some(ast) = parse_error.ast.take() {
                    error = Some(parse_error.into());
                    *ast
                } else {
                    return Self {
                        error: Some(parse_error.into()),
                        ..Default::default()
                    };
                }
            }
        };
        if error.is_none() {
            if let Err(compile_error) = Compiler::compile_ast(ast.clone(), None, default()) {
                error = Some(compile_error.into())
            }
        }
        SourceInfoBuilder::from_ast(&ast, script, uri, info_cache).build(error)
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn get_definition_from_location(&self, location: Location) -> Option<Definition> {
        self.definitions
            .binary_search_by(|definition| {
                cmp_range_to_range(&definition.location.range, location.range)
            })
            .ok()
            .map(|i| self.definitions[i].clone())
    }

    pub fn get_definition_from_position(&self, position: Position) -> Option<Definition> {
        self.definitions
            .binary_search_by(|definition| {
                cmp_range_to_position(&definition.location.range, position)
            })
            .ok()
            .and_then(|i| self.get_definition_from_location(self.definitions[i].location.clone()))
    }

    pub fn get_referenced_definition_location(&self, position: Position) -> Option<Location> {
        self.references
            .binary_search_by(|reference| {
                cmp_range_to_position(&reference.location.range, position)
            })
            .ok()
            .map(|i| self.references[i].definition.clone())
    }

    pub fn get_definition_location(&self, position: Position) -> Option<Location> {
        self.get_referenced_definition_location(position)
            .or_else(|| {
                self.definitions
                    .binary_search_by(|definition| {
                        cmp_range_to_position(&definition.location.range, position)
                    })
                    .ok()
                    .map(|i| self.definitions[i].location.clone())
            })
    }

    pub fn find_references(
        &self,
        position: Position,
        include_definition: bool,
    ) -> Option<FindReferencesIter> {
        self.get_definition_location(position)
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

    pub fn get_autocomplete_items(&self, position: Position) -> impl Iterator<Item = &Definition> {
        self.definitions.iter().filter(move |definition| {
            definition.location.range.end <= position
                && (definition.top_level || self.is_definition_in_scope(definition, position))
        })
    }

    fn is_definition_in_scope(&self, definition: &Definition, position: Position) -> bool {
        // Find which scope the position is in
        let position_scope_index = self.get_scope_at_position(position);

        // Check if the definition's scope is accessible from the position's scope
        self.is_scope_accessible(definition.scope_index, position_scope_index)
    }

    fn get_scope_at_position(&self, position: Position) -> usize {
        // Find the innermost scope that contains the position
        for (index, scope) in self.scopes.iter().enumerate().rev() {
            if position >= scope.range.start && position <= scope.range.end {
                return index;
            }
        }
        0 // Root scope if no specific scope found
    }

    fn is_scope_accessible(&self, definition_scope: usize, position_scope: usize) -> bool {
        // A definition is accessible if:
        // 1. It's in the same scope as the position
        // 2. It's in a parent scope of the position
        // 3. It's in the root scope (global)

        if definition_scope == position_scope {
            return true;
        }

        // Check if definition_scope is a parent of position_scope
        let mut current_scope = position_scope;
        while current_scope < self.scopes.len() {
            if current_scope == definition_scope {
                return true;
            }
            // Move to parent scope
            if let Some(parent) = self.scopes[current_scope].parent_scope {
                current_scope = parent;
            } else {
                break;
            }
        }

        false
    }
}

/// A location in a source file, identified by [Url] and [Range]
#[derive(Clone, Debug, PartialEq)]
pub struct Location {
    pub uri: Arc<Uri>,
    pub range: Range,
}

impl Location {
    fn new(uri: Arc<Uri>, span: Span) -> Self {
        Self {
            uri,
            range: koto_span_to_lsp_range(span),
        }
    }
}

impl From<Location> for tower_lsp_server::lsp_types::Location {
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

impl Iterator for FindReferencesIter<'_> {
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

fn cmp_range_to_position(range: &Range, position: Position) -> Ordering {
    if range.start > position {
        Ordering::Greater
    } else if range.end <= position {
        Ordering::Less
    } else {
        Ordering::Equal
    }
}

fn cmp_range_to_range(range_lhs: &Range, range_rhs: Range) -> Ordering {
    if range_lhs.start < range_rhs.start {
        Ordering::Less
    } else if range_lhs.end > range_rhs.end {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Definition {
    location: Location,
    pub id: StringSlice<usize>,
    pub kind: SymbolKind,
    // true for definitions at the top-level of the script, i.e. not in a function
    top_level: bool,
    // The scope index this definition belongs to
    scope_index: usize,
    children: Option<Vec<Definition>>,
}

impl Definition {
    fn new(
        id: StringSlice<usize>,
        location: Location,
        kind: SymbolKind,
        top_level: bool,
        scope_index: usize,
        children: Vec<Definition>,
    ) -> Self {
        Self {
            location,
            id,
            kind,
            top_level,
            scope_index,
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
    pub id: StringSlice<usize>,
}

struct SourceInfoBuilder<'i> {
    // The contents of the file that's being scanned
    script: String,
    // The uri of the file that's being scanned
    uri: Arc<Uri>,
    // A cache that gets checked while importing modules
    #[allow(unused)]
    info_cache: &'i mut InfoCache,
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
    // All scopes found in the file
    scopes: Vec<ScopeInfo>,
    // Current scope index stack (for nested scopes)
    scope_stack: Vec<usize>,
}

impl<'i> SourceInfoBuilder<'i> {
    fn from_ast(ast: &Ast, script: String, uri: Arc<Uri>, info_cache: &'i mut InfoCache) -> Self {
        let mut result = Self {
            script,
            uri,
            info_cache,
            frames: Vec::new(),
            definitions: Vec::new(),
            references: Vec::new(),
            scopes: Vec::new(),
            scope_stack: Vec::new(),
        };

        // Add global scope
        result.scopes.push(ScopeInfo {
            range: Range {
                start: Position {
                    line: 0,
                    character: 0,
                },
                end: Position {
                    line: u32::MAX,
                    character: u32::MAX,
                },
            },
            kind: ScopeKind::Global,
            parent_scope: None,
        });
        result.scope_stack.push(0); // Start in global scope

        if let Some(entry_point) = ast.entry_point() {
            result.visit_node(entry_point, Context::new(ast));
        };

        result
    }

    fn build(mut self, error: Option<Error>) -> SourceInfo {
        // Sort the definitions, they get added in pop_frame so they aren't in order
        self.definitions
            .sort_by_key(|definition| definition.location.range.start);

        // References should already be sorted
        debug_assert!(is_sorted::IsSorted::is_sorted_by_key(
            &mut self.references.iter(),
            |reference| reference.location.range.start
        ));

        SourceInfo {
            source: self.script,
            definitions: self.definitions,
            references: self.references,
            scopes: self.scopes,
            error,
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
            | Node::Type { .. }
            | Node::Ignored(..) => {}
            // Map entries are visited in visit_map
            Node::MapEntry(..) => {}
            // Nodes with a single child node that should be visited
            Node::Nested(node)
            | Node::RangeFrom { start: node }
            | Node::RangeTo { end: node, .. }
            | Node::UnaryOp { value: node, .. }
            | Node::Loop { body: node }
            | Node::Throw(node)
            | Node::Yield(node)
            | Node::PackedExpression(node)
            | Node::Debug {
                expression: node, ..
            } => {
                self.visit_node(*node, ctx.default());
            }
            // Nodes with a list of nodes that should be visited
            Node::List(nodes)
            | Node::Tuple {
                elements: nodes, ..
            }
            | Node::TempTuple(nodes) => self.visit_nested(nodes, ctx.default()),
            Node::Block(nodes) => {
                let block_span = *ctx.ast.span(node_index);
                let block_range = koto_span_to_lsp_range(block_span);
                let _scope_index = self.push_scope(block_range, ScopeKind::Block);

                self.visit_nested(nodes, ctx.default());

                self.pop_scope();
            }
            // Nodes with an optional child node
            Node::Break(maybe_node) | Node::Return(maybe_node) => {
                if let Some(node) = maybe_node {
                    self.visit_node(*node, ctx.default());
                }
            }
            Node::Id(id, _type_hint) => {
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
            Node::Map { entries, .. } => child_definitions = self.visit_map(entries, &ctx),
            Node::MainBlock { body, local_count } => {
                self.push_frame(*local_count);
                self.visit_nested(body, ctx.default());
                self.pop_frame();
            }
            Node::Function(info) => {
                let function_span = *ctx.ast.span(node_index);
                let function_range = koto_span_to_lsp_range(function_span);
                let _scope_index = self.push_scope(function_range, ScopeKind::Function);

                self.push_frame(info.local_count);
                self.visit_node(info.args, ctx.default());
                self.visit_node(info.body, ctx.default());
                self.pop_frame();

                self.pop_scope();
            }
            Node::FunctionArgs { args, .. } => {
                let definitions = &mut self.frame_mut().definitions;
                definitions.reserve(definitions.capacity() + args.len());
                self.visit_nested(args, ctx.with_ids_as_definitions());
            }
            Node::Import { from, items } => self.visit_import(from, items, &ctx),
            Node::Export(item) => {
                // Set id_is_definition to true to count exported map keys as definitions
                self.visit_node(*item, ctx.with_ids_as_definitions());
            }
            Node::Assign {
                target, expression, ..
            } => self.visit_assign(*target, *expression, &ctx),
            Node::MultiAssign {
                targets,
                expression,
                ..
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
                    self.visit_node(*arm, ctx.default());
                }
            }
            Node::MatchArm {
                patterns,
                condition,
                expression,
            } => {
                for pattern in patterns.iter() {
                    self.visit_node(*pattern, ctx.with_ids_as_definitions());
                }
                if let Some(condition) = condition {
                    self.visit_node(*condition, ctx.default());
                }
                self.visit_node(*expression, ctx.default());
            }
            Node::Switch(arms) => {
                for arm in arms.iter() {
                    self.visit_node(*arm, ctx.default());
                }
            }
            Node::SwitchArm {
                condition,
                expression,
            } => {
                if let Some(condition) = condition {
                    self.visit_node(*condition, ctx.default());
                }
                self.visit_node(*expression, ctx.default());
            }
            Node::PackedId(maybe_id) => {
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
                for catch_block in &info.catch_blocks {
                    self.visit_node(catch_block.arg, ctx.with_ids_as_definitions());
                    self.visit_node(catch_block.block, ctx.default());
                }
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

    fn visit_map(&mut self, entries: &[AstIndex], ctx: &Context) -> Vec<Definition> {
        let mut child_definitions = Vec::new();

        for entry in entries.iter() {
            let entry_node = ctx.node(*entry);
            let (key_node, value) = match &entry_node.node {
                Node::Id(..) => (entry_node, None),
                Node::MapEntry(key, value) => (ctx.node(*key), Some(*value)),
                _ => continue,
            };

            match &key_node.node {
                Node::Str(s) => self.visit_string(&s, ctx.default()),
                Node::Id(id, _type_hint) => {
                    // Shorthand syntax?
                    if value.is_none() {
                        self.add_reference(*id, entry_node, ctx.ast);
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
                            self.current_scope_index(),
                            vec![], // TODO - nested child definitions?
                        ))
                    }
                }
                Node::Meta(key_id, maybe_name) => {
                    let field_id = match maybe_name {
                        Some(name) => format!("{key_id} {}", ctx.string(*name).as_str()),
                        None => format!("{key_id}"),
                    };
                    child_definitions.push(Definition::new(
                        field_id.into(),
                        Location::new(self.uri.clone(), *ctx.ast.span(key_node.span)),
                        SymbolKind::FIELD,
                        self.frames.len() == 1, // TODO - use frame.is_top_level?
                        self.current_scope_index(),
                        vec![], // TODO - nested child definitions?
                    ))
                }
                _ => {}
            }
            if let Some(value) = value {
                self.visit_node(value, ctx.default());
            }
        }

        child_definitions
    }

    fn visit_import(&mut self, from: &[AstIndex], items: &[ImportItem], ctx: &Context) {
        let mut maybe_module: Option<Arc<SourceInfo>> = None;

        // from ...
        for (i, from_index) in from.iter().enumerate() {
            let from_node = ctx.node(*from_index);
            match &from_node.node {
                Node::Id(id, _type_hint) => {
                    let id_string = ctx.string(*id);
                    if i == 0 {
                        // check for matching definition
                        if self.get_definition(id_string.as_str()).is_some() {
                            // The module name was defined earlier in the script, so add a reference
                            self.add_reference(*id, from_node, ctx.ast);
                        } else if let Some(module_url) = self.find_module(id_string.as_str()) {
                            self.analyze_module(module_url.clone());
                            maybe_module = self.info_cache.get(&module_url);
                            if maybe_module.is_some() {
                                // The module was successfully analyzed, so add a reference
                                self.add_reference_with_definition(
                                    id_string,
                                    *ctx.span(from_node),
                                    Location::new(module_url.clone(), Span::default()),
                                );
                            }
                        }
                    } else if let Some(module) = &maybe_module {
                        if let Some(definition) = module
                            .top_level_definitions()
                            .find(|definition| definition.id == id_string)
                        {
                            // Add a reference here to enable go-to-definition
                            self.add_reference_with_definition(
                                id_string,
                                *ctx.span(from_node),
                                definition.location.clone(),
                            );
                        }
                        maybe_module = None;
                    }
                }
                Node::Str(s) => self.visit_string(s, ctx.default()),
                _ => {}
            }
        }

        // import ...
        for item in items.iter() {
            let item_node = ctx.node(item.item);
            match (&item_node.node, item.name) {
                (Node::Id(id, _), maybe_as) => {
                    let id_string = ctx.string(*id);
                    let (as_string, as_node) = if let Some(as_index) = maybe_as {
                        let as_node = ctx.node(as_index);
                        let Node::Id(as_id, _) = &as_node.node else {
                            unreachable!("TODO - return error")
                        };
                        (Some(ctx.string(*as_id)), Some(as_node))
                    } else {
                        (None, None)
                    };

                    if let Some(module) = &maybe_module {
                        if let Some(definition) = module
                            .top_level_definitions()
                            .find(|definition| definition.id == id_string)
                        {
                            self.add_imported_definition(definition.clone());
                            // Also add a reference here to enable go-to-definition
                            self.add_reference_with_definition(
                                id_string,
                                *ctx.span(item_node),
                                definition.location.clone(),
                            );
                            if let (Some(as_node), Some(as_string)) = (as_node, as_string) {
                                // ...and also a reference for the alias
                                self.add_reference_with_definition(
                                    as_string.clone(),
                                    *ctx.span(as_node),
                                    definition.location.clone(),
                                );
                                // Add a local definition for the alias
                                self.add_definition(
                                    as_string,
                                    SymbolKind::VARIABLE,
                                    vec![],
                                    as_node,
                                    ctx.ast,
                                );
                            }
                            continue;
                        }
                    } else if from.is_empty() {
                        // `from` wasn't used, so the import item is a module
                        // check for matching definition
                        let module_name = ctx.string(*id);

                        if self.get_definition(module_name.as_str()).is_some() {
                            // The module name was defined earlier in the script, so add a reference
                            self.add_reference(*id, item_node, ctx.ast);
                        } else if let Some(module_url) = self.find_module(module_name.as_str()) {
                            self.analyze_module(module_url.clone());
                            if self.info_cache.get(&module_url).is_some() {
                                // The module was successfully analyzed, so add a reference
                                let module_location =
                                    Location::new(module_url.clone(), Span::default());
                                self.add_reference_with_definition(
                                    module_name,
                                    *ctx.span(item_node),
                                    module_location.clone(),
                                );
                                if let Some(as_node) = as_node {
                                    // ...and also a reference for the alias
                                    self.add_reference_with_definition(
                                        as_string.clone().unwrap(), // as_string is defined with as_node
                                        *ctx.span(as_node),
                                        module_location,
                                    );
                                }
                            }
                        }
                    }

                    // Add a local definition for the imported item
                    let name = as_string.unwrap_or(id_string);
                    let name_node = as_node.unwrap_or(item_node);
                    self.add_definition(name, SymbolKind::VARIABLE, vec![], name_node, ctx.ast)
                }
                (Node::Str(s), maybe_as) => {
                    self.visit_string(s, ctx.default());
                    if let Some(name) = maybe_as {
                        let name_node = ctx.node(name);
                        if let Node::Id(id, _type_hint) = &name_node.node {
                            self.add_definition(
                                ctx.string(*id),
                                SymbolKind::VARIABLE,
                                vec![],
                                name_node,
                                ctx.ast,
                            )
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn analyze_module(&mut self, url: Arc<Uri>) {
        let Some(path) = url.to_file_path() else {
            return;
        };
        let Ok(metadata) = fs::metadata(&path) else {
            return;
        };
        let Ok(modified_time) = metadata.modified() else {
            return;
        };
        if self
            .info_cache
            .get_versioned(&url, modified_time.into())
            .is_some()
        {
            return;
        }
        let Ok(script) = fs::read_to_string(&path) else {
            return;
        };
        let info = SourceInfo::new(script, url.clone(), self.info_cache);
        self.info_cache.insert(url, modified_time.into(), info);
    }

    fn visit_assign(&mut self, target: AstIndex, expression: AstIndex, ctx: &Context) {
        let target_node = ctx.node(target);
        match &target_node.node {
            Node::Id(id, _type_hint) => {
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
                    target_id.into(),
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
            ChainNode::NullCheck => {}
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

    fn get_definition(&self, id: &str) -> Option<&Definition> {
        for frame in self.frames.iter().rev() {
            if let Some(definition) = frame.get_definition(id) {
                return Some(definition);
            }
        }
        None
    }

    fn add_definition(
        &mut self,
        id: StringSlice<usize>,
        kind: SymbolKind,
        children: Vec<Definition>,
        node: &AstNode,
        ast: &Ast,
    ) {
        let span = ast.span(node.span);
        let uri = self.uri.clone();
        self.frame_mut()
            .add_definition(id, Location::new(uri, *span), kind, children);
    }

    fn add_imported_definition(&mut self, definition: Definition) {
        self.frame_mut().add_imported_definition(definition);
    }

    fn add_reference(&mut self, id: ConstantIndex, node: &AstNode, ast: &Ast) {
        let id = ast.constants().get_string_slice(id);

        let Some(definition) = self.get_definition(id.as_str()) else {
            return;
        };

        let span = ast.span(node.span);
        let location = definition.location.clone();
        self.add_reference_with_definition(id, *span, location);
    }

    fn add_reference_with_definition(
        &mut self,
        id: StringSlice<usize>,
        span: Span,
        definition: Location,
    ) {
        self.references.push(Reference {
            location: Location::new(self.uri.clone(), span),
            definition,
            id,
        });
    }

    fn find_module(&self, name: &str) -> Option<Arc<Uri>> {
        if let Some(script_path_buf) = self.uri.to_file_path() {
            // find modules at directory of current script
            let script_path = script_path_buf.parent();
            let Ok(path) = koto_bytecode::find_module(name, script_path) else {
                return None;
            };
            let Some(url) = Uri::from_file_path(path) else {
                return None;
            };
            Some(Arc::new(url))
        } else {
            None
        }
    }

    fn frame_mut(&mut self) -> &mut Frame {
        self.frames.last_mut().expect("Missing frame")
    }

    fn push_scope(&mut self, range: Range, kind: ScopeKind) -> usize {
        let parent_scope = self.scope_stack.last().copied();
        let scope_index = self.scopes.len();

        self.scopes.push(ScopeInfo {
            range,
            kind,
            parent_scope,
        });

        self.scope_stack.push(scope_index);
        scope_index
    }

    fn pop_scope(&mut self) {
        self.scope_stack.pop();
    }

    fn current_scope_index(&self) -> usize {
        *self.scope_stack.last().unwrap_or(&0)
    }

    fn push_frame(&mut self, locals_capacity: usize) {
        self.frames.push(Frame {
            definitions: Vec::with_capacity(locals_capacity),
            imported_definitions: Vec::new(),
            top_level: self.frames.is_empty(),
            scope_index: self.current_scope_index(),
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
    imported_definitions: Vec<Definition>,
    top_level: bool,
    scope_index: usize,
}

impl Frame {
    fn add_definition(
        &mut self,
        id: StringSlice<usize>,
        location: Location,
        kind: SymbolKind,
        children: Vec<Definition>,
    ) {
        self.definitions.push(Definition::new(
            id,
            location,
            kind,
            self.top_level,
            self.scope_index,
            children,
        ));
    }

    fn add_imported_definition(&mut self, definition: Definition) {
        self.imported_definitions.push(definition);
    }

    fn get_definition(&self, id: &str) -> Option<&Definition> {
        self.definitions
            .iter()
            .rev() // reversed so that the most recent matching definition is found
            .find(|definition| definition.id.as_str() == id)
            .or_else(|| {
                self.imported_definitions
                    .iter()
                    .rev()
                    .find(|definition| definition.id.as_str() == id)
            })
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

    fn string(&self, constant_index: ConstantIndex) -> StringSlice<usize> {
        self.ast.constants().get_string_slice(constant_index)
    }

    fn span(&self, node: &AstNode) -> &Span {
        self.ast.span(node.span)
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
    use std::str::FromStr;
    use tower_lsp_server::lsp_types::Position;

    fn position(line: u32, character: u32) -> Position {
        Position { line, character }
    }

    fn range(line: u32, column: u32, length: u32) -> Range {
        Range {
            start: position(line, column),
            end: position(line, column + length),
        }
    }

    fn test_uri() -> Arc<Uri> {
        Arc::new(Uri::from_str("file:///test.koto").unwrap())
    }

    mod goto_definition {
        use super::*;

        fn goto_definition_test(script: &str, cases: &[(Position, Option<Range>)]) -> Result<()> {
            let mut info_cache = InfoCache::default();
            let info = SourceInfo::new(script.to_string(), test_uri(), &mut info_cache);

            for (i, (position, expected)) in cases.iter().enumerate() {
                let result = info.get_definition_location(*position);
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
            let mut info_cache = InfoCache::default();
            let info = SourceInfo::new(script.to_string(), test_uri(), &mut info_cache);

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
                            references.clone().count(),
                            "reference count mismatch in case {i}",
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
        fn let_expression() -> Result<()> {
            let script = "\
let x: Number = 42
1 + x
";
            find_references_test(
                script,
                &[
                    (position(0, 4), Some(&[range(1, 4, 1)]), false),
                    (
                        position(0, 4),
                        Some(&[range(0, 4, 1), range(1, 4, 1)]),
                        true,
                    ),
                    (
                        position(1, 4),
                        Some(&[range(0, 4, 1), range(1, 4, 1)]),
                        true,
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
from some_other_module import bar
x = |y| y.baz = bar
";
            find_references_test(
                script,
                &[(
                    position(0, 31), // bar
                    Some(&[range(0, 30, 3), range(1, 16, 3)]),
                    true,
                )],
            )
        }
    }

    mod top_level_definitions {
        use tower_lsp_server::lsp_types::SymbolKind;

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
            let mut info_cache = InfoCache::default();
            let info = SourceInfo::new(script.to_string(), test_uri(), &mut info_cache);
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
        fn assignments_before_error() -> Result<()> {
            let script = "\
a = 42
foo = |n|
  x = n
  x * x

!

x, y, z = f()
";
            top_level_definitions_test(
                script,
                &[
                    definition(range(0, 0, 1), "a", SymbolKind::NUMBER, &[]),
                    definition(range(1, 0, 3), "foo", SymbolKind::FUNCTION, &[]),
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

    mod autocomplete {
        use super::*;

        fn autocomplete_test(script: &str, cases: &[(Position, &[&str])]) -> Result<()> {
            let mut info_cache = InfoCache::default();
            let info = SourceInfo::new(script.to_string(), test_uri(), &mut info_cache);

            for (i, (position, expected_names)) in cases.iter().enumerate() {
                let items: Vec<_> = info.get_autocomplete_items(*position).collect();
                let actual_names: Vec<_> = items.iter().map(|def| def.id.as_str()).collect();

                for (j, expected_name) in expected_names.iter().enumerate() {
                    if j >= actual_names.len() {
                        panic!(
                            "mismatch in case {i}: expected '{expected_name}' but ran out of items"
                        );
                    }
                    if !actual_names.contains(expected_name) {
                        panic!(
                            "mismatch in case {i}: expected '{expected_name}' but found {actual_names:?}"
                        );
                    }
                }

                // Check that we don't have extra unexpected items
                for actual_name in &actual_names {
                    if !expected_names.contains(actual_name) {
                        panic!(
                            "mismatch in case {i}: unexpected item '{actual_name}' in {actual_names:?}",
                        );
                    }
                }
            }

            Ok(())
        }

        #[test]
        fn basic_variables() -> Result<()> {
            let script = "\
a = 42
b = 99
c = a + b
";
            autocomplete_test(
                script,
                &[
                    (position(0, 6), &["a"]), // At end of first line, 'a' should be available
                    (position(1, 0), &["a"]), // At start of second line, 'a' is available
                    (position(2, 0), &["a", "b"]), // After 'a' and 'b' are defined
                    (position(2, 10), &["a", "b", "c"]), // After all are defined
                ],
            )
        }

        #[test]
        fn function_parameters() -> Result<()> {
            let script = "\
x = 42
f = |a, b|
  y = a + b + x
  y
g = f(1, 2)
";
            autocomplete_test(
                script,
                &[
                    (position(1, 0), &["x"]),                // Before function definition
                    (position(2, 2), &["x", "f", "a", "b"]), // Inside function, parameters are now visible
                    (position(4, 0), &["x", "f"]), // After function definition, parameters not visible
                    (position(4, 10), &["x", "f", "g"]), // After g is defined
                ],
            )
        }

        #[test]
        fn map_assignments() -> Result<()> {
            let script = "\
data = 
  name: \"test\"
  value: 42
result = data.name
";
            autocomplete_test(
                script,
                &[
                    (position(3, 0), &["data"]),            // After map is defined
                    (position(3, 20), &["data", "result"]), // After result is defined
                ],
            )
        }

        #[test]
        fn multi_assignment() -> Result<()> {
            let script = "\
a, b, c = 1, 2, 3
sum = a + b + c
";
            autocomplete_test(
                script,
                &[
                    (position(1, 0), &["a", "b", "c"]), // After multi-assignment
                    (position(1, 15), &["a", "b", "c", "sum"]), // After sum is defined
                ],
            )
        }

        #[test]
        fn import_statements() -> Result<()> {
            let script = "\
import foo, bar as baz
x = foo + baz
";
            autocomplete_test(
                script,
                &[
                    (position(1, 0), &["foo", "baz"]),       // After imports
                    (position(1, 13), &["foo", "baz", "x"]), // After x is defined
                ],
            )
        }

        #[test]
        fn nested_scopes_simplified() -> Result<()> {
            let script = "\
a = 1
f = |x|
  b = 2
  |y| x + y + a + b
result = f(10)(20)
";
            autocomplete_test(
                script,
                &[
                    (position(2, 2), &["a", "f", "x"]), // Inside function - parameters visible
                    (position(3, 2), &["a", "f", "x", "b"]), // Inside nested function, outer scope visible
                    (position(4, 0), &["a", "f"]), // At start of result line, local scope not visible
                    (position(4, 18), &["a", "f", "result"]), // After result is defined
                ],
            )
        }

        #[test]
        fn export_statements() -> Result<()> {
            let script = "\
x = 42
export
  value: x
  name: \"test\"
";
            autocomplete_test(
                script,
                &[
                    (position(1, 0), &["x"]),                   // Before export
                    (position(3, 10), &["x", "value", "name"]), // After export with fields
                ],
            )
        }

        #[test]
        fn control_flow() -> Result<()> {
            let script = "\
x = 10
if x > 5
  y = x * 2
else
  y = x / 2
z = y + 1
";
            autocomplete_test(
                script,
                &[
                    (position(2, 2), &["x"]),           // Inside if block
                    (position(4, 2), &["x", "y"]),      // Inside else block - first y is visible
                    (position(5, 0), &["x", "y"]), // After if/else - both y definitions are visible (last one wins)
                    (position(5, 9), &["x", "y", "z"]), // After z is defined
                ],
            )
        }

        #[test]
        fn complex_nested_scopes() -> Result<()> {
            let script = "\
outer_var = 42
outer_func = |param1|
  local_var = param1 * 2
  inner_func = |param2|
    inner_var = param2 + local_var + outer_var
    inner_var
  inner_func(10)

another_top_level = 99
";
            autocomplete_test(
                script,
                &[
                    (position(2, 2), &["outer_var", "outer_func", "param1"]), // Inside outer function
                    (
                        position(4, 4),
                        &[
                            "outer_var",
                            "outer_func",
                            "param1",
                            "local_var",
                            "inner_func",
                            "param2",
                        ],
                    ), // Inside inner function
                    (position(8, 0), &["outer_var", "outer_func"]), // After functions, local vars not visible
                    (
                        position(8, 20),
                        &["outer_var", "outer_func", "another_top_level"],
                    ), // After another_top_level
                ],
            )
        }

        #[test]
        fn function_parameters_and_locals() -> Result<()> {
            let script = "\
global = 1
func = |a, b, c|
  x = a + b
  y = c + global
  z = x + y
  z

result = func(1, 2, 3)
";
            autocomplete_test(
                script,
                &[
                    (position(2, 2), &["global", "func", "a", "b", "c"]), // Parameters visible
                    (position(3, 2), &["global", "func", "a", "b", "c", "x"]), // Previous locals visible
                    (position(4, 2), &["global", "func", "a", "b", "c", "x", "y"]), // All locals visible
                    (position(7, 0), &["global", "func"]), // Outside function, locals not visible
                    (position(7, 22), &["global", "func", "result"]), // After result defined
                ],
            )
        }

        #[test]
        fn scope_boundaries() -> Result<()> {
            let script = "\
a = 1
first_func = |x|
  b = x + a
  b

c = 2
second_func = |y|
  d = y + c
  d

e = 3
";
            autocomplete_test(
                script,
                &[
                    (position(2, 2), &["a", "first_func", "x"]), // Inside first function
                    (position(6, 0), &["a", "first_func", "c"]), // Between functions
                    (
                        position(7, 2),
                        &["a", "first_func", "c", "second_func", "y"],
                    ), // Inside second function
                    (
                        position(10, 6),
                        &["a", "first_func", "c", "second_func", "e"],
                    ), // After e is completed
                ],
            )
        }
    }

    mod ast_scope_tracking {
        use super::*;

        #[test]
        fn test_ast_based_scope_tracking() {
            let code = r#"
x = 42

f = |a| 
  y = a + 1
  inner = |b|
    z = b + y
    w = z + 1
    w
  inner(10)

g = |c|
  d = c * 2
  d

result = f(5) + g(3)
"#;

            let mut info_cache = InfoCache::default();
            let source_info = SourceInfo::new(code.to_string(), test_uri(), &mut info_cache);

            // Test autocomplete inside inner function (should see a, y, b, z, w, x, f, inner)
            let inner_pos = Position {
                line: 7,
                character: 6,
            };
            let inner_completions: Vec<_> = source_info.get_autocomplete_items(inner_pos).collect();

            // Test autocomplete inside g function (should see c, d, x, f, g but not y, z, w)
            let g_pos = Position {
                line: 12,
                character: 6,
            };
            let g_completions: Vec<_> = source_info.get_autocomplete_items(g_pos).collect();

            // Verify the inner function can see variables from parent scopes
            assert!(inner_completions.iter().any(|c| c.id.as_str() == "a")); // from f function
            assert!(inner_completions.iter().any(|c| c.id.as_str() == "y")); // from f function  
            assert!(inner_completions.iter().any(|c| c.id.as_str() == "b")); // from inner function
            assert!(inner_completions.iter().any(|c| c.id.as_str() == "z")); // from inner function
            assert!(inner_completions.iter().any(|c| c.id.as_str() == "w")); // from inner function
            assert!(inner_completions.iter().any(|c| c.id.as_str() == "x")); // global
            assert!(inner_completions.iter().any(|c| c.id.as_str() == "f")); // global
            assert!(inner_completions.iter().any(|c| c.id.as_str() == "inner")); // from f function

            // Verify g function can see local and global variables but not f function variables
            assert!(g_completions.iter().any(|c| c.id.as_str() == "c")); // from g function
            assert!(g_completions.iter().any(|c| c.id.as_str() == "d")); // from g function
            assert!(g_completions.iter().any(|c| c.id.as_str() == "x")); // global
            assert!(g_completions.iter().any(|c| c.id.as_str() == "f")); // global
            assert!(g_completions.iter().any(|c| c.id.as_str() == "g")); // global
            assert!(!g_completions.iter().any(|c| c.id.as_str() == "a")); // not from f function
            assert!(!g_completions.iter().any(|c| c.id.as_str() == "y")); // not from f function
            assert!(!g_completions.iter().any(|c| c.id.as_str() == "inner")); // not from f function
            assert!(!g_completions.iter().any(|c| c.id.as_str() == "b")); // not from inner function
            assert!(!g_completions.iter().any(|c| c.id.as_str() == "z")); // not from inner function
            assert!(!g_completions.iter().any(|c| c.id.as_str() == "w")); // not from inner function
        }
    }
}
