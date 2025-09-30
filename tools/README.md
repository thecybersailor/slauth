# Tools

This directory contains utility tools for the @cybersailor/slauth-ts project.

## generate_templates.py

A Python script that automatically generates `pkg/consts/tmpl.go` from template files in the `templates/` directory.

### Usage

```bash
# Generate templates directly
python3 tools/generate_templates.py

# Or use the Makefile target
make generate-templates

# Or run the full build (includes template generation)
make all
```

### How it works

1. Scans the `templates/` directory for subdirectories (e.g., `email/`, `sms/`)
2. Reads all `.tmpl` files in each subdirectory
3. Generates Go code that embeds the template content as byte arrays
4. Outputs the result to `pkg/consts/tmpl.go`

### Template structure

The script expects templates to be organized as:
```
templates/
├── email/
│   ├── change-email.tmpl
│   ├── confirm-signup.tmpl
│   └── ...
└── sms/
    ├── reauthentication.tmpl
    └── verification-code.tmpl
```

Each template file will be accessible in Go as:
```go
BuildinTemplates["email"]["change-email"]
BuildinTemplates["sms"]["verification-code"]
```

### Integration with Makefile

The template generation is integrated into the main build process:
- `make generate-templates` - Generate templates only
- `make all` - Full build including template generation
- Templates are automatically regenerated when template files change
