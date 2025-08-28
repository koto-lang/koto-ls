use koto_bytecode::Compiler;
use koto_parser::{
    Ast, AstIndex, AstNode, AstString, ChainNode, ConstantIndex, ImportItem, Node, Parser, Span,
    StringContents, StringNode, StringSlice,
};
use std::{cmp::Ordering, collections::HashSet, fs, sync::Arc};
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
    // A vec of all definitions
    pub definitions: Vec<Definition>,
    // All definition IDs, sorted by start position
    pub definitions_by_range: Vec<(Range, DefinitionId)>,
    // A vec of all references
    pub references: Vec<Reference>,
    // All reference IDs, sorted by start position
    pub references_by_range: Vec<(Range, ReferenceId)>,
    /// A vec of all frames, sorted by start position
    pub frames: Vec<Frame>,
    /// If an error was encountered while compiling the script it's cached here
    pub error: Option<Error>,
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
        if error.is_none()
            && let Err(compile_error) = Compiler::compile_ast(ast.clone(), None, default())
        {
            error = Some(compile_error.into())
        }
        SourceInfoBuilder::from_ast(&ast, script, uri, info_cache).build(error)
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn get_definition_from_location(&self, location: Location) -> Option<&Definition> {
        self.definitions_by_range
            .binary_search_by(|(range, _)| cmp_range_to_range(range, location.range))
            .ok()
            .map(|i| &self.definitions_by_range[i])
            .and_then(|definition| self.definitions.get(definition.1.0))
    }

    pub fn get_definition_from_position(&self, position: Position) -> Option<&Definition> {
        self.definitions_by_range
            .binary_search_by(|(range, _)| cmp_range_to_position(range, position))
            .ok()
            .map(|i| &self.definitions_by_range[i])
            .and_then(|definition| self.definitions.get(definition.1.0))
    }

    pub fn get_referenced_definition_location(&self, position: Position) -> Option<Location> {
        self.references_by_range
            .binary_search_by(|(range, _)| cmp_range_to_position(range, position))
            .ok()
            .map(|i| &self.references_by_range[i])
            .and_then(|reference| {
                self.references
                    .get(reference.1.0)
                    .map(|refe| refe.definition.clone())
            })
    }

    pub fn get_definition_location(&self, position: Position) -> Option<Location> {
        self.get_referenced_definition_location(position)
            .or_else(|| {
                self.get_definition_from_position(position)
                    .map(|definition| {
                        // If the definition has a remote location, return it
                        // e.g imported definition
                        if let Some(ref remote) = definition.imported_location {
                            remote.clone()
                        } else {
                            definition.location.clone()
                        }
                    })
            })
    }

    pub fn find_references(
        &self,
        position: Position,
        include_definition: bool,
    ) -> Option<FindReferencesIter<'_>> {
        self.get_definition_location(position).map(|definition| {
            // TODO: chains the iterator with other files ?
            // so we can see all references to this definition
            FindReferencesIter {
                definition,
                references: self.references.iter(),
                include_definition,
            }
        })
    }

    pub fn top_level_definitions(&self) -> impl Iterator<Item = &Definition> {
        let top_frame = FrameId(0);
        self.definitions
            .iter()
            .filter(move |definition| definition.frame_id == top_frame)
    }

    pub fn get_available_definitions_at_location(&self, location: Location) -> Vec<&Definition> {
        let mut names = HashSet::new();
        let mut available_definitions = Vec::new();

        // Find the innermost frame that contains this location
        let mut innermost_frame_id = None;
        for (frame_id, frame) in self.frames.iter().enumerate().rev() {
            if frame.location.range.start <= location.range.start
                && frame.location.range.end >= location.range.end
            {
                innermost_frame_id = Some(FrameId(frame_id));
                break;
            }
        }

        // Append definitions from frame tree
        let mut current_frame_id = innermost_frame_id;
        while let Some(fid) = current_frame_id {
            if let Some(frame) = self.frames.get(fid.0) {
                for def_id in frame.definitions.iter().rev() {
                    if let Some(definition) = self.definitions.get(def_id.0)
                        // Remove definition that are later in the scope
                        && cmp_range_to_position(&definition.location.range, location.range.start)
                            != Ordering::Greater
                        && !names.contains(definition.id.as_str())
                    {
                        available_definitions.push(definition);
                        names.insert(definition.id.as_str());
                    }
                }
            }
            current_frame_id = self.frames.get(fid.0).and_then(|frame| frame.parent);
        }

        available_definitions.sort_by_key(|def| def.location.range.start);
        available_definitions
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

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct DefinitionId(pub usize);

impl From<DefinitionId> for usize {
    fn from(value: DefinitionId) -> Self {
        value.0
    }
}

impl From<usize> for DefinitionId {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Definition {
    pub location: Location,
    pub id: StringSlice<usize>,
    pub kind: SymbolKind,
    pub children: Option<Vec<Definition>>,
    pub frame_id: FrameId,
    /// If this definition was imported from another module, the location in that module
    pub imported_location: Option<Location>,
}

impl Definition {
    fn new(
        id: StringSlice<usize>,
        location: Location,
        kind: SymbolKind,
        children: Vec<Definition>,
        frame_id: FrameId,
    ) -> Self {
        Self {
            location,
            id,
            kind,
            children: if children.is_empty() {
                None
            } else {
                Some(children)
            },
            frame_id,
            imported_location: None,
        }
    }

    fn imported(
        id: StringSlice<usize>,
        location: Location,
        kind: SymbolKind,
        redirect_location: Location,
        frame_id: FrameId,
    ) -> Self {
        Self {
            location,
            id,
            kind,
            children: None,
            frame_id,
            imported_location: Some(redirect_location),
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

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct ReferenceId(pub usize);

impl From<ReferenceId> for usize {
    fn from(value: ReferenceId) -> Self {
        value.0
    }
}

impl From<usize> for ReferenceId {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Reference {
    pub location: Location,
    pub definition: Location,
    pub id: StringSlice<usize>,
    pub frame_id: FrameId,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UnresolvedReference {
    pub location: Location,
    pub id: StringSlice<usize>,
    pub frame_id: FrameId,
}

struct SourceInfoBuilder<'i> {
    // The contents of the file that's being scanned
    script: String,
    // The uri of the file that's being scanned
    uri: Arc<Uri>,
    // A cache that gets checked while importing modules
    #[allow(unused)]
    info_cache: &'i mut InfoCache,
    // All frames found in the file.
    frames: Vec<Frame>,
    // A stack of frames, each time a function is encountered a new frame is added to the stack
    frame_stack: Vec<FrameId>,
    // All definitions that have been found in the file.
    //
    // Definitions are collected in frames and then appended to this vec when the frame is popped
    // off the stack. This results in an unsorted ordering, so the definitions get sorted in the
    // build function.
    definitions: Vec<Definition>,
    // A map from position to definition ID for quick lookups
    definitions_by_position: Vec<(Range, DefinitionId)>,
    // All references that have been found in the file.
    // The references get added as soon as they're encountered in the AST, so they're always sorted.
    references: Vec<Reference>,
    // A map from position to reference ID for quick lookups
    references_by_position: Vec<(Range, ReferenceId)>,
    // Unresolved references are collected and resolved in build function
    unresolved_references: Vec<UnresolvedReference>,
}

impl<'i> SourceInfoBuilder<'i> {
    fn from_ast(ast: &Ast, script: String, uri: Arc<Uri>, info_cache: &'i mut InfoCache) -> Self {
        let mut result = Self {
            script,
            uri,
            info_cache,
            frames: Vec::new(),
            frame_stack: Vec::new(),
            definitions: Vec::new(),
            definitions_by_position: Vec::new(),
            references: Vec::new(),
            references_by_position: Vec::new(),
            unresolved_references: Vec::new(),
        };

        if let Some(entry_point) = ast.entry_point() {
            result.visit_node(entry_point, Context::new(ast));
        };

        result
    }

    fn get_definition_from_frame(
        &self,
        id: &str,
        frame_id: FrameId,
        location: &Location,
    ) -> Option<(DefinitionId, &Definition)> {
        let mut current_frame_id = Some(frame_id);
        while let Some(fid) = current_frame_id {
            // Search definitions in the current scope
            for (index, definition) in self.definitions.iter().enumerate().rev() {
                let ordering = cmp_range_to_range(&definition.location.range, location.range);
                if definition.frame_id == fid
                    && definition.id.as_str() == id
                    && ordering != Ordering::Greater
                {
                    return Some((DefinitionId(index), definition));
                }
            }
            // Move to parent scope if available
            current_frame_id = self.frames.get(fid.0).and_then(|frame| frame.parent);
        }
        None
    }

    fn resolve_references(&mut self) {
        let references = std::mem::take(&mut self.unresolved_references);
        for unresolved in references {
            let id = unresolved.id.as_str();
            let frame_id = unresolved.frame_id;
            let Some((_, def)) = self.get_definition_from_frame(id, frame_id, &unresolved.location)
            else {
                continue;
            };

            self.references.push(Reference {
                location: unresolved.location.clone(),
                definition: def.location.clone(),
                id: unresolved.id.clone(),
                frame_id: unresolved.frame_id,
            });

            let reference_id = ReferenceId(self.references.len() - 1);
            self.references_by_position
                .push((unresolved.location.range, reference_id));
        }
    }

    fn build(mut self, error: Option<Error>) -> SourceInfo {
        // Resolve unresolved references
        self.resolve_references();

        // Sort definitions and references by their start position
        self.definitions_by_position
            .sort_by_key(|(range, _)| range.start);
        self.references_by_position
            .sort_by_key(|(range, _)| range.start);

        SourceInfo {
            source: self.script,
            definitions: self.definitions,
            definitions_by_range: self.definitions_by_position,
            references: self.references,
            references_by_range: self.references_by_position,
            error,
            frames: self.frames,
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
            | Node::TempTuple(nodes)
            | Node::Block(nodes) => self.visit_nested(nodes, ctx.default()),
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
                self.push_frame(*local_count, ctx.ast, node);
                self.visit_nested(body, ctx.default());
                self.pop_frame();
            }
            Node::Function(info) => {
                self.push_frame(info.local_count, ctx.ast, node);
                self.visit_node(info.args, ctx.default());
                self.visit_node(info.body, ctx.default());
                self.pop_frame();
            }
            Node::FunctionArgs { args, .. } => {
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
                if let Some(id) = maybe_id
                    && ctx.id_is_definition
                {
                    self.add_definition(
                        ctx.string(*id),
                        SymbolKind::VARIABLE,
                        vec![],
                        node,
                        ctx.ast,
                    );
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
                Node::Str(s) => self.visit_string(s, ctx.default()),
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
                            vec![],                  // TODO - nested child definitions?
                            self.current_frame_id(), // Use the current frame id
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
                        vec![],                  // TODO - nested child definitions?
                        self.current_frame_id(), // Use the current frame id
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
            let location = Location::new(self.uri.clone(), *ctx.ast.span(from_node.span));
            match &from_node.node {
                Node::Id(id, _type_hint) => {
                    let id_string = ctx.string(*id);
                    if i == 0 {
                        // check for matching definition
                        if self.get_definition(id_string.as_str(), &location).is_some() {
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
            let location = Location::new(self.uri.clone(), *ctx.ast.span(item_node.span));
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
                            // Also add a reference here to enable go-to-definition
                            self.add_reference_with_definition(
                                id_string.clone(),
                                *ctx.span(item_node),
                                definition.location.clone(),
                            );

                            if let (Some(as_node), Some(as_string)) = (as_node, as_string) {
                                // Add a local definition for the alias
                                let _ = self.add_definition(
                                    as_string.clone(),
                                    SymbolKind::VARIABLE,
                                    vec![],
                                    as_node,
                                    ctx.ast,
                                );

                                // ...and also a reference for the alias
                                self.add_reference_with_definition(
                                    as_string.clone(),
                                    *ctx.span(as_node),
                                    definition.location.clone(),
                                );
                            } else {
                                // If there's no alias, just import the definition so we can see it in autocompletion
                                self.add_imported_definition(
                                    *ctx.span(item_node),
                                    definition.clone(),
                                );
                            }
                            continue;
                        }
                    } else if from.is_empty() {
                        // `from` wasn't used, so the import item is a module
                        // check for matching definition
                        let module_name = ctx.string(*id);

                        if self
                            .get_definition(module_name.as_str(), &location)
                            .is_some()
                        {
                            // The module name was defined earlier in the script, so add a reference
                            self.add_reference(*id, item_node, ctx.ast);
                        } else if let Some(module_url) = self.find_module(module_name.as_str()) {
                            self.analyze_module(module_url.clone());
                            if self.info_cache.get(&module_url).is_some() {
                                // The module was successfully analyzed, so add a reference
                                self.add_reference_with_definition(
                                    module_name,
                                    *ctx.span(item_node),
                                    Location::new(module_url.clone(), Span::default()),
                                );
                                if let Some(as_node) = as_node {
                                    // ...and also a reference for the alias
                                    self.add_reference_with_definition(
                                        as_string.clone().unwrap(), // as_string is defined with as_node
                                        *ctx.span(as_node),
                                        Location::new(module_url.clone(), Span::default()),
                                    );
                                }
                            }
                        }
                    }

                    // Add a local definition for the imported item
                    let name = as_string.unwrap_or(id_string);
                    let name_node = as_node.unwrap_or(item_node);
                    self.add_definition(name, SymbolKind::VARIABLE, vec![], name_node, ctx.ast);
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
                            );
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

    fn get_definition(&self, id: &str, location: &Location) -> Option<(DefinitionId, &Definition)> {
        let current_frame = self.current_frame_id();
        self.get_definition_from_frame(id, current_frame, location)
    }

    fn add_definition(
        &mut self,
        id: StringSlice<usize>,
        kind: SymbolKind,
        children: Vec<Definition>,
        node: &AstNode,
        ast: &Ast,
    ) -> DefinitionId {
        let span = ast.span(node.span);
        let uri = self.uri.clone();
        self.definitions.push(Definition::new(
            id.clone(),
            Location::new(uri, *span),
            kind,
            children,
            self.current_frame_id(),
        ));

        let definition_id = DefinitionId(self.definitions.len() - 1);
        self.definitions_by_position
            .push((koto_span_to_lsp_range(*span), definition_id));

        self.current_frame_mut().definitions.push(definition_id);
        definition_id
    }

    fn add_imported_definition(&mut self, local_span: Span, imported_definition: Definition) {
        let local_location = Location::new(self.uri.clone(), local_span);
        let range = imported_definition.location.range;
        self.definitions.push(Definition::imported(
            imported_definition.id,
            local_location,
            imported_definition.kind,
            imported_definition.location.clone(),
            self.current_frame_id(),
        ));

        let definition_id = DefinitionId(self.definitions.len() - 1);
        self.definitions_by_position.push((range, definition_id));
        self.current_frame_mut().definitions.push(definition_id);
    }

    fn add_reference(&mut self, id: ConstantIndex, node: &AstNode, ast: &Ast) {
        let id = ast.constants().get_string_slice(id);
        let span = ast.span(node.span);
        let location = Location::new(self.uri.clone(), *span);

        let Some((_, definition)) = self.get_definition(id.as_str(), &location) else {
            self.add_unresolved_reference(id, *span);
            return;
        };

        // Check if the definition is imported
        let location = if let Some(remote) = &definition.imported_location {
            remote.clone()
        } else {
            definition.location.clone()
        };

        self.add_reference_with_definition(id, *span, location);
    }

    fn add_unresolved_reference(&mut self, id: StringSlice<usize>, span: Span) {
        self.unresolved_references.push(UnresolvedReference {
            location: Location::new(self.uri.clone(), span),
            id,
            frame_id: self.current_frame_id(),
        });
    }

    fn add_reference_with_definition(
        &mut self,
        id: StringSlice<usize>,
        span: Span,
        definition_location: Location,
    ) {
        self.references.push(Reference {
            location: Location::new(self.uri.clone(), span),
            definition: definition_location,
            id,
            frame_id: self.current_frame_id(),
        });

        let reference_id = ReferenceId(self.references.len() - 1);
        self.references_by_position
            .push((koto_span_to_lsp_range(span), reference_id));
    }

    fn current_frame_mut(&mut self) -> &mut Frame {
        let current_frame_id = self.current_frame_id();
        self.frames
            .get_mut(current_frame_id.0)
            .expect("Missing current frame")
    }

    fn current_frame_id(&self) -> FrameId {
        // The frame stack should never be empty
        self.frame_stack
            .last()
            .copied()
            .expect("Missing current frame")
    }

    fn find_module(&self, name: &str) -> Option<Arc<Uri>> {
        if let Some(script_path_buf) = self.uri.to_file_path() {
            // find modules at directory of current script
            let script_path = script_path_buf.parent();
            let Ok(path) = koto_bytecode::find_module(name, script_path) else {
                return None;
            };
            let url = Uri::from_file_path(path)?;
            Some(Arc::new(url))
        } else {
            None
        }
    }

    fn push_frame(&mut self, locals_capacity: usize, ast: &Ast, node: &AstNode) {
        let span = ast.span(node.span);
        let uri = self.uri.clone();
        let parent = self.frame_stack.last().copied();
        self.definitions.reserve_exact(locals_capacity);
        self.frames.push(Frame {
            location: Location::new(uri, *span),
            parent,
            definitions: Vec::with_capacity(locals_capacity),
        });

        self.frame_stack.push(FrameId(self.frames.len() - 1));
    }

    fn pop_frame(&mut self) {
        self.frame_stack.pop();
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrameId(usize);

impl From<FrameId> for usize {
    fn from(value: FrameId) -> Self {
        value.0
    }
}

impl From<usize> for FrameId {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub location: Location,
    pub parent: Option<FrameId>,
    pub definitions: Vec<DefinitionId>,
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

    fn range_at_position(line: u32, character: u32) -> Range {
        Range::new(position(line, character), position(line, character))
    }

    fn location_at_position(uri: Arc<Uri>, line: u32, character: u32) -> Location {
        Location {
            uri,
            range: range_at_position(line, character),
        }
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
                    _ => panic!("mismatch in case {i}: expected: {expected:?}, actual: {result:?}"),
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

        #[test]
        fn fib() -> Result<()> {
            let script = r#"fib = |nf|
    switch
        nf <= 0 then 0
        nf == 1 then 1
        else (fib nf - 1) + (fib nf - 2)"#;

            goto_definition_test(
                script,
                &[
                    // Test fib definition and references
                    (position(4, 14), Some(range(0, 0, 3))), // fib in (fib nf - 1) -> fib definition
                    (position(4, 29), Some(range(0, 0, 3))), // fib in (fib nf - 2) -> fib definition
                    // Test nf parameter definition and references
                    (position(2, 8), Some(range(0, 7, 2))), // nf in "nf <= 0" -> nf parameter
                    (position(3, 8), Some(range(0, 7, 2))), // nf in "nf == 1" -> nf parameter
                    (position(4, 18), Some(range(0, 7, 2))), // nf in "fib nf - 1" -> nf parameter
                    (position(4, 33), Some(range(0, 7, 2))), // nf in "fib nf - 2" -> nf parameter
                    // Test that we can't find definition at random positions
                    (position(1, 4), None),  // switch keyword
                    (position(2, 12), None), // <= operator
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

        #[test]
        fn fib_references() -> Result<()> {
            let script = r#"fib = |nf|
        switch
            nf <= 0 then 0
            nf == 1 then 1
            else (fib nf - 1) + (fib nf - 2)"#;

            find_references_test(
                script,
                &[
                    (
                        position(0, 0),                            // fib definition
                        Some(&[range(4, 18, 3), range(4, 33, 3)]), // two recursive calls
                        false,
                    ),
                    (
                        position(0, 0), // fib definition (include definition)
                        Some(&[range(0, 0, 3), range(4, 18, 3), range(4, 33, 3)]),
                        true,
                    ),
                    (
                        position(0, 7), // nf parameter
                        Some(&[
                            range(2, 12, 2), // nf <= 0
                            range(3, 12, 2), // nf == 1
                            range(4, 22, 2), // fib nf - 1
                            range(4, 37, 2), // fib nf - 2
                        ]),
                        false,
                    ),
                    (
                        position(0, 7), // nf parameter (include definition)
                        Some(&[
                            range(0, 7, 2),  // parameter definition
                            range(2, 12, 2), // nf <= 0
                            range(3, 12, 2), // nf == 1
                            range(4, 22, 2), // fib nf - 1
                            range(4, 37, 2), // fib nf - 2
                        ]),
                        true,
                    ),
                ],
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

    mod completions {
        use super::*;

        fn assert_completions(completions: &[&Definition], expected: &[&str]) {
            assert_eq!(
                completions.len(),
                expected.len(),
                "Completion count mismatch, expected: {}, found: {}",
                expected.len(),
                completions.len()
            );
            let names: Vec<String> = completions
                .iter()
                .map(|d| d.id.as_str().to_string())
                .collect();
            for i in 0..expected.len() {
                assert_eq!(names[i], expected[i]);
            }
        }

        #[test]
        fn simple_variables() {
            let script = "\
v_x = 42
v_y = \"hello\"
v_z = true
v_x + v
";

            let mut info_cache = InfoCache::default();
            let info = SourceInfo::new(script.to_string(), test_uri(), &mut info_cache);

            let location = location_at_position(test_uri(), 3, 7);
            let completions = info.get_available_definitions_at_location(location);

            assert_eq!(completions.len(), 3);

            let expected = ["v_x", "v_y", "v_z"];
            assert_completions(&completions, &expected);
        }

        #[test]
        fn function_scope() {
            let script = "\
v_x = 1
v_foo = |v_a, v_b|
  v_local_var = v_a + v_b
  v_x + v_local_var + v
";

            let mut info_cache = InfoCache::default();
            let info = SourceInfo::new(script.to_string(), test_uri(), &mut info_cache);

            let location = location_at_position(test_uri(), 3, 22);
            let completions = info.get_available_definitions_at_location(location);

            assert_completions(&completions, &["v_x", "v_foo", "v_a", "v_b", "v_local_var"]);
        }

        #[test]
        fn nested_scopes() {
            let script = "\
v_outer = 1
v_f = |v_x|
  v_inner = 2
  v_g = |v_y|
    v_nested = 3
    v_outer + v_inner + v_x + v_y + v
";

            let mut info_cache = InfoCache::default();
            let info = SourceInfo::new(script.to_string(), test_uri(), &mut info_cache);

            let location = location_at_position(test_uri(), 5, 36);
            let completions = info.get_available_definitions_at_location(location);

            let expected = ["v_outer", "v_f", "v_x", "v_inner", "v_g", "v_y", "v_nested"];
            assert_completions(&completions, &expected);
        }

        #[test]
        fn excludes_out_of_scope() {
            let script = "\
v_global_var = 1
v_f = |v_param|
  v_local_var = 2
  v_local_var + v_param
v_g = |v_other_param|
  v_other_local = 3
  v_global_var + v_other_local + v
";

            let mut info_cache = InfoCache::default();
            let info = SourceInfo::new(script.to_string(), test_uri(), &mut info_cache);

            let location = location_at_position(test_uri(), 6, 34);
            let completions = info.get_available_definitions_at_location(location);

            let expected = [
                "v_global_var",
                "v_f",
                "v_g",
                "v_other_param",
                "v_other_local",
            ];
            assert_completions(&completions, &expected);
        }

        #[test]
        fn top_level() {
            let script = "\
v_x = 1
v_y = 2
v_f = |v_a| v_a * 2
";

            let mut info_cache = InfoCache::default();
            let info = SourceInfo::new(script.to_string(), test_uri(), &mut info_cache);

            let location = location_at_position(test_uri(), 3, 0);
            let completions = info.get_available_definitions_at_location(location);

            let expected = ["v_x", "v_y", "v_f"];
            assert_completions(&completions, &expected);
        }

        #[test]
        fn empty_script() {
            let script = "";

            let mut info_cache = InfoCache::default();
            let info = SourceInfo::new(script.to_string(), test_uri(), &mut info_cache);

            let location = location_at_position(test_uri(), 0, 0);
            let completions = info.get_available_definitions_at_location(location);

            assert_eq!(completions.len(), 0);
        }

        #[test]
        fn variable_shadowing() {
            let script = "\
v_x = \"global\"
v_f = |v_x|
  v_x = 56
  v_x + v
";

            let mut info_cache = InfoCache::default();
            let info = SourceInfo::new(script.to_string(), test_uri(), &mut info_cache);

            let location = location_at_position(test_uri(), 3, 9);
            let completions = info.get_available_definitions_at_location(location);

            let expected = ["v_f", "v_x"];
            assert_completions(&completions, &expected);

            let v_x_definition = completions
                .iter()
                .find(|d| d.id.as_str() == "v_x")
                .expect("v_x definition not found");

            assert_eq!(v_x_definition.frame_id, FrameId(1));
            assert_eq!(v_x_definition.kind, SymbolKind::NUMBER);
        }

        #[test]
        fn imports() {
            let script = "\
import v_foo
from v_bar import v_baz
v_local_var = 1
v_foo + v_baz + v
";

            let mut info_cache = InfoCache::default();
            let info = SourceInfo::new(script.to_string(), test_uri(), &mut info_cache);

            let location = location_at_position(test_uri(), 3, 17);
            let completions = info.get_available_definitions_at_location(location);

            let expected = ["v_foo", "v_baz", "v_local_var"];
            assert_completions(&completions, &expected);
        }
    }
}
