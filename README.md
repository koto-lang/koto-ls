# koto-ls

An implementation of the [Language Server Protocol][lsp] for the
[Koto programming language][koto].

## Installation

The latest published version of `koto-ls` can be installed by running
`cargo install koto-ls`.

To install the development version of `koto-ls`, run `cargo install --path .` in the current directory.

## Features

Along with reporting compilation errors,
the following LSP features are supported by `koto-ls`:

- [Document formatting][document-formatting]
- [Document highlights][document-highlights]
- [Find references][find-references]
- [Get document symbols][document-symbols]
- [Goto definition][goto-definition]
- [Hover][hover]
- [Rename symbol][rename-symbol]

## Editor Setup


### [Helix][helix]

Helix has built-in support for Koto since version `25.01`, and will make use of `koto-ls` if it's available in your path.

For older versions, `koto-ls` can be registered as a language server in your [`languages.toml` file][helix].

```toml
[language-server.koto-ls]
command = "koto-ls"

[[language]]
name = "koto"
scope = "source.koto"
injection-regex = "koto"
file-types = ["koto"]
comment-token = "#"
indent = { tab-width = 2, unit = "  " }
roots = []
language-servers = [ "koto-ls" ]
```

### Neovim

`koto-ls` can be used with neovim's built-in LSP support by creating an autocmd
that runs each time a `.koto` file is opened.

```lua
vim.api.nvim_create_autocmd("FileType", {
  pattern = "koto",
  callback = function()
    vim.lsp.start({
      cmd = { "koto-ls" },
      root_dir = vim.fn.getcwd(),
    })
  end
})
```

### [Sublime Text][sublime]

After following the [LSP setup instructions][sublime-lsp] and installing the [`koto` package][sublime-koto], you can enable `koto-ls` by adding the following to the `"clients"` list in your LSP settings:

```json
"koto-ls": {
    "enabled": true,
    "command": ["koto-ls"],
    "selector": "source.koto"
}
```


### [Zed][zed]

`koto-ls` can be used with zed's LSP support via user-installable [`koto-zed`][koto-zed] extension that runs each time a `.koto` file is opened.


[document-formatting]: https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_formatting
[document-highlights]: https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_documentHighlight
[document-symbols]: https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_documentSymbol
[find-references]: https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_references
[goto-definition]: https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_definition
[helix]: https://docs.helix-editor.com/languages.html
[hover]: https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_hover
[koto-zed]: https://github.com/koto-lang/koto-zed
[koto]: https://koto.dev
[lsp]: https://microsoft.github.io/language-server-protocol/
[rename-symbol]: https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_rename
[sublime]: https://www.sublimetext.com
[sublime-koto]: https://packagecontrol.io/packages/Koto
[sublime-lsp]: https://lsp.sublimetext.io
[zed]: https://zed.dev/extensions?query=Koto&filter=language-servers
