.PHONY: build test fmt clean update run bump doc hooks

# Build the project (warnings are errors)
build: fmt
	RUSTFLAGS="-D warnings" cargo build

# Run unit tests (warnings are errors) — inline `#[cfg(test)] mod tests` blocks
test:
	RUSTFLAGS="-D warnings" cargo test --workspace --lib

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
run:
ifdef dir
	cargo run -p malwi -- $(dir) $(args)
else
	@echo "Usage: make run dir=<path> args=\"--concurrency 4 --max-time 5m\""
endif

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
