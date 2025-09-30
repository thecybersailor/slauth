#!/usr/bin/env python3
"""
Template generator tool for @cybersailor/slauth-ts
Generates tmpl.go from template files in templates/ directory
"""

import os
import sys
from pathlib import Path

def read_template_file(file_path):
    """Read template file and return its content"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return f.read()

def generate_tmpl_go(templates_dir, output_file):
    """Generate tmpl.go file from template files"""
    
    # Initialize the Go file content
    go_content = '''package consts

var BuildinTemplates = map[string]map[string][]byte{
'''
    
    # Process each category (email, sms)
    for category in ['email', 'sms']:
        category_dir = templates_dir / category
        if not category_dir.exists():
            continue
            
        go_content += f'\t"{category}": {{\n'
        
        # Get all .tmpl files in the category directory
        template_files = sorted(category_dir.glob('*.tmpl'))
        
        for template_file in template_files:
            template_name = template_file.stem  # filename without extension
            template_content = read_template_file(template_file)
            
            # Escape the template content for Go string literal
            escaped_content = template_content.replace('`', '` + "`" + `')
            
            go_content += f'\t\t"{template_name}": []byte(`{escaped_content}`),\n'
        
        go_content += '\t},\n'
    
    go_content += '}\n'
    
    # Write the generated content to output file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(go_content)
    
    print(f"Generated {output_file} with {len(template_files)} templates")

def main():
    # Get the project root directory (parent of tools directory)
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    templates_dir = project_root / 'templates'
    output_file = project_root / 'pkg' / 'consts' / 'tmpl.go'
    
    # Check if templates directory exists
    if not templates_dir.exists():
        print(f"Error: Templates directory not found at {templates_dir}")
        sys.exit(1)
    
    # Ensure output directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Generate the tmpl.go file
    generate_tmpl_go(templates_dir, output_file)
    print("Template generation completed successfully!")

if __name__ == '__main__':
    main()
