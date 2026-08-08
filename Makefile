.PHONY: build test fmt clean update run osint download bump doc hooks

# Sourced rather than `include`d: .env is shell, not make.
dotenv = if [ -f .env ]; then set -a; . ./.env; set +a; fi

build: fmt
	RUSTFLAGS="-D warnings" cargo build

test:
	RUSTFLAGS="-D warnings" cargo test --workspace --bins

doc:
	RUSTDOCFLAGS="-D warnings -D rustdoc::broken-intra-doc-links -D rustdoc::private-intra-doc-links" \
	  cargo doc --no-deps -p malwi

fmt:
	cargo fmt

clean:
	cargo clean

update:
	cargo update

# Exit 2 is the malicious-verdict signal under --fail-fast, not a failure.
run:
ifdef dir
	@$(dotenv); cargo run -p malwi -- analyze $(dir) $(args) || [ $$? -eq 2 ]
else
	@echo "Usage: make run dir=<path> args=\"--concurrency 4 --max-time 5m\""
endif

osint:
	@$(dotenv); cargo run -p malwi -- osint $(focus) $(args)

download:
ifdef prompt
	@$(dotenv); cargo run -p malwi -- download $(prompt) $(args)
else
	@echo "Usage: make download prompt=\"py stanza 1.14.0\""
endif

part ?= patch
bump: test
	@current=$$(grep '^version' crates/malwi/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/'); \
	IFS='.' read -r major minor patch <<< "$$current"; \
	case "$(part)" in \
		major) major=$$((major + 1)); minor=0; patch=0;; \
		minor) minor=$$((minor + 1)); patch=0;; \
		patch) patch=$$((patch + 1));; \
		*) echo "Unknown part: $(part). Use major, minor, or patch."; exit 1;; \
	esac; \
	new="$$major.$$minor.$$patch"; \
	sed -i '' "s/^version = \"$$current\"/version = \"$$new\"/" crates/malwi/Cargo.toml; \
	cargo check --workspace --quiet; \
	git add -A && git commit -m "v$$new" && \
	git tag "v$$new" && \
	echo "$$current → $$new" && \
	echo "Tagged v$$new — now run:" && \
	echo "  git push && git push --tags"

hooks:
	@mkdir -p .claude/hooks
	@cp hooks/*.sh .claude/hooks/
	@chmod +x .claude/hooks/*.sh
	@if [ ! -f .claude/settings.local.json ]; then echo '{}' > .claude/settings.local.json; fi
	@jq -s '.[0] * .[1]' .claude/settings.local.json hooks/hooks.json > .claude/settings.local.tmp \
		&& mv .claude/settings.local.tmp .claude/settings.local.json
	@echo "Hooks installed into .claude/settings.local.json"
