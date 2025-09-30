package types

import "context"

type MessageTemplateResolver interface {
	GetTemplate(domainCode, messageType, templateName string) ([]byte, bool)
}

type MessageTemplate interface {
	Render(ctx context.Context, data map[string]interface{}) (MessageRenderResult, error)
}

type MessageRender interface {
	Render(ctx context.Context, template []byte, data map[string]interface{}) (MessageRenderResult, error)
}

type MessageRenderResult interface {
	GetType() string
	GetSubject() *string
	GetBody() string
}

type FileTemplateResult struct {
	Type    string
	Subject *string
	Body    string
}

func (r *FileTemplateResult) GetType() string {
	return r.Type
}

func (r *FileTemplateResult) GetSubject() *string {
	return r.Subject
}

func (r *FileTemplateResult) GetBody() string {
	return r.Body
}
