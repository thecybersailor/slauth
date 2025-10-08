package services

import (
	"os"
	"path/filepath"
)

type FileTemplateResolver struct {
	basePath string
}

func NewFileTemplateResolver(basePath string) *FileTemplateResolver {
	return &FileTemplateResolver{
		basePath: basePath,
	}
}

func (f *FileTemplateResolver) GetTemplate(instanceId, messageType, templateName string) ([]byte, bool) {

	templatePath := filepath.Join(f.basePath, messageType, templateName+".tmpl")

	content, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, false
	}

	return content, true
}
