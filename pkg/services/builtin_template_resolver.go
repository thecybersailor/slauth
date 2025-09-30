package services

import (
	"github.com/thecybersailor/slauth/pkg/consts"
)

type BuiltinTemplateResolver struct{}

func NewBuiltinTemplateResolver() *BuiltinTemplateResolver {
	return &BuiltinTemplateResolver{}
}

func (b *BuiltinTemplateResolver) GetTemplate(domainCode, messageType, templateName string) ([]byte, bool) {

	if templates, exists := consts.BuildinTemplates[messageType]; exists {

		if templateBytes, found := templates[templateName]; found {
			return templateBytes, true
		}
	}

	return nil, false
}
