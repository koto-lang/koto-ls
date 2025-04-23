checks: fmt test

fmt:
  cargo fmt --all -- --check

test *args:
  cargo test {{args}}

update_koto: 
  cargo update -p koto_bytecode -p koto_parser

watch command *args:
  cargo watch -s "just {{command}} {{args}}"
