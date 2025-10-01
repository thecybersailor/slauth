# slauth Build System

.DEFAULT_GOAL := all

# Go source files
GO_FILES := $(shell find . -name "*.go" -not -path "./vendor/*")

# Include modular makefiles
include tools/mk/build.mk
include tools/mk/test.mk
include tools/mk/e2e.mk
include tools/mk/dev.mk
include tools/mk/clean.mk
include tools/mk/help.mk
