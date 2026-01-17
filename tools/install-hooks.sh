#!/bin/bash
# Install Git hooks for test and lint verification before pushing to main branch

set -e

HOOK_FILE=".git/hooks/pre-push"

echo "Installing pre-push hook for test and lint verification..."

cat > "$HOOK_FILE" << 'EOF'
#!/bin/bash
# Auto-generated pre-push hook for test and lint verification
# This hook ensures all Go tests pass and lint checks pass before pushing to main branch

while read local_ref local_sha remote_ref remote_sha
do
    # Extract branch name from ref
    if [[ $remote_ref =~ refs/heads/(.+) ]]; then
        branch="${BASH_REMATCH[1]}"
        
        # Only enforce verification for main branch
        if [[ "$branch" == "main" ]]; then
            echo "==> Verifying tests and lint for main branch push..."
            
            # Check if checks marker file exists
            if [ ! -f .checks-passed ]; then
                echo ""
                echo "ERROR: No checks marker found."
                echo "Please run tests and lint before pushing to main:"
                echo "  make test  # Run tests"
                echo "  make lint  # Run lint"
                echo ""
                exit 1
            fi
            
            # Check if any Go file is newer than checks marker
            go_files_modified=false
            modified_files=""
            
            while IFS= read -r -d '' file; do
                if [ "$file" -nt .checks-passed ]; then
                    go_files_modified=true
                    modified_files="${modified_files}  - ${file}\n"
                fi
            done < <(find . -name "*.go" -not -path "./vendor/*" -not -path "./.git/*" -type f -print0)
            
            if [ "$go_files_modified" = true ]; then
                echo ""
                echo "ERROR: Go files have been modified since last checks."
                echo "Modified files:"
                echo -e "$modified_files"
                echo "Please run tests and lint before pushing to main:"
                echo "  make test         # SQLite (default)"
                echo "  make test-mysql   # MySQL"
                echo "  make test-pgsql   # PostgreSQL"
                echo "  make lint         # Run lint checks"
                echo ""
                exit 1
            fi
            
            echo "==> Tests and lint verified. Proceeding with push to main..."
        fi
    fi
done

exit 0
EOF

# Make the hook executable
chmod +x "$HOOK_FILE"

echo ""
echo "Pre-push hook installed successfully!"
echo ""
echo "How it works:"
echo "  1. Modify Go files and commit changes"
echo "  2. Run 'make test' to verify all tests pass"
echo "  3. Run 'make lint' to verify all lint checks pass"
echo "  4. Push to main branch - hook will auto-verify"
echo ""
echo "The hook will:"
echo "  - Allow push if tests and lint are up to date"
echo "  - Block push if Go files changed since last checks"
echo "  - Only check pushes to main branch"
echo ""

