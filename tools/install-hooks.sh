#!/bin/bash
# Install Git hooks for test verification before pushing to main branch

set -e

HOOK_FILE=".git/hooks/pre-push"

echo "Installing pre-push hook for test verification..."

cat > "$HOOK_FILE" << 'EOF'
#!/bin/bash
# Auto-generated pre-push hook for test verification
# This hook ensures all Go tests pass before pushing to main branch

while read local_ref local_sha remote_ref remote_sha
do
    # Extract branch name from ref
    if [[ $remote_ref =~ refs/heads/(.+) ]]; then
        branch="${BASH_REMATCH[1]}"
        
        # Only enforce test verification for main branch
        if [[ "$branch" == "main" ]]; then
            echo "==> Verifying tests for main branch push..."
            
            # Check if test marker file exists
            if [ ! -f .test-passed ]; then
                echo ""
                echo "ERROR: No test marker found."
                echo "Please run tests before pushing to main:"
                echo "  make test"
                echo ""
                exit 1
            fi
            
            # Check if any Go file is newer than test marker
            go_files_modified=false
            modified_files=""
            
            while IFS= read -r -d '' file; do
                if [ "$file" -nt .test-passed ]; then
                    go_files_modified=true
                    modified_files="${modified_files}  - ${file}\n"
                fi
            done < <(find . -name "*.go" -not -path "./vendor/*" -not -path "./.git/*" -type f -print0)
            
            if [ "$go_files_modified" = true ]; then
                echo ""
                echo "ERROR: Go files have been modified since last test."
                echo "Modified files:"
                echo -e "$modified_files"
                echo "Please run tests before pushing to main:"
                echo "  make test         # SQLite (default)"
                echo "  make test-mysql   # MySQL"
                echo "  make test-pgsql   # PostgreSQL"
                echo ""
                exit 1
            fi
            
            echo "==> Tests verified. Proceeding with push to main..."
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
echo "  3. Push to main branch - hook will auto-verify"
echo ""
echo "The hook will:"
echo "  - Allow push if tests are up to date"
echo "  - Block push if Go files changed since last test"
echo "  - Only check pushes to main branch"
echo ""

