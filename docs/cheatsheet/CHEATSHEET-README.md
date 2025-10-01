**When user attaches this document, it indicates the user wants to generate a new cheatsheet document.**

Cheatsheets are primarily for AI to learn how to utilize system capabilities for coding.
Cheatsheets are mainly for AI, with AI following the documentation.
Considering AI context limitations, documentation should be concise and avoid redundancy.
To ensure consistency across multiple executions, plan steps should be listed, including involved files, modified files, and naming for new files.

# Cheatsheet Requirements
* A standard cheatsheet should not exceed 200 lines
* Cheatsheets record repeatable steps without explaining principles
* Cheatsheets should not include usage instructions, be absolutely concise, directly executable by AI to reduce context overhead
* If there are test cases, attach paths to test cases
* If there is reference code, attach paths to a few reference code samples
* Include search keywords in the codebase, can be regular expressions that AI can understand and execute
* Refer to docs/cheatsheet/pin-response-testing.md as a template
* Automatically update docs/cheatsheet/README.md after generating new cheatsheet