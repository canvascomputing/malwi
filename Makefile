.PHONY: build test fmt clean update run research bump doc hooks

# Prefix for any recipe that runs the binary, so provider credentials in .env
# reach it without being exported by hand. Sourced rather than `include`d,
# because .env is shell, not make: quotes and `#` in a value would not survive
# make's own parsing.
dotenv = if [ -f .env ]; then set -a; . ./.env; set +a; fi

# Build the project (warnings are errors)
build: fmt
	RUSTFLAGS="-D warnings" cargo build

# Run unit tests (warnings are errors) — inline `#[cfg(test)] mod tests` blocks
test:
	RUSTFLAGS="-D warnings" cargo test --workspace --bins

# Build rustdoc (warnings are errors; broken intra-doc links fail)
doc:
	RUSTDOCFLAGS="-D warnings -D rustdoc::broken-intra-doc-links -D rustdoc::private-intra-doc-links" \
	  cargo doc --no-deps -p malwi

# Format all code
fmt:
	cargo fmt

# Remove build artifacts
clean:
	cargo clean

# Update dependencies
update:
	cargo update

# Run the scanner against a directory
# Usage: make run dir=./src args="--concurrency 4"
# Exit 2 is the malicious-verdict signal under --fail-fast, not a build failure,
# so it is tolerated; every other non-zero code still fails.
run:
ifdef dir
	@$(dotenv); cargo run -p malwi -- scan $(dir) $(args) || [ $$? -eq 2 ]
else
	@echo "Usage: make run dir=<path> args=\"--concurrency 4 --max-time 5m\""
endif

# Research gaps in the attack-pattern knowledge and install the pages that pass
# verification. Needs BRAVE_API_KEY alongside the provider credentials in .env.
# Usage: make research
#        make research topic="npm registry attacks" args="--max-gaps 3"
research:
	@$(dotenv); cargo run -p malwi -- research $(topic) $(args)

# Bump version, test, commit, and tag for release: make bump part=patch (default), minor, or major
# GitHub Actions handles the crates.io publish via trusted publishing after you push the tag
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

# Install Claude Code hooks into .claude/settings.local.json
hooks:
	@mkdir -p .claude/hooks
	@cp hooks/*.sh .claude/hooks/
	@chmod +x .claude/hooks/*.sh
	@if [ ! -f .claude/settings.local.json ]; then echo '{}' > .claude/settings.local.json; fi
	@jq -s '.[0] * .[1]' .claude/settings.local.json hooks/hooks.json > .claude/settings.local.tmp \
		&& mv .claude/settings.local.tmp .claude/settings.local.json
	@echo "Hooks installed into .claude/settings.local.json"
