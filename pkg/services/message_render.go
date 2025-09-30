package services

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/thecybersailor/slauth/pkg/types"
)

type TemplateInfo struct {
	Subject string            `json:"subject"`
	Content string            `json:"content"`
	Headers map[string]string `json:"headers"`
}

type MessageRenderService struct{}

func NewMessageRenderService() *MessageRenderService {
	return &MessageRenderService{}
}

func (mrs *MessageRenderService) ParseTemplateFile(templatePath string) (*TemplateInfo, error) {
	file, err := os.Open(templatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open template file %s: %v", templatePath, err)
	}
	defer file.Close()

	info := &TemplateInfo{
		Headers: make(map[string]string),
	}

	scanner := bufio.NewScanner(file)
	var contentLines []string
	headerFinished := false

	for scanner.Scan() {
		line := scanner.Text()

		if !headerFinished {

			if strings.HasPrefix(line, "#") {

				headerLine := strings.TrimPrefix(line, "#")
				headerLine = strings.TrimSpace(headerLine)

				if headerLine != "" {
					parts := strings.SplitN(headerLine, ":", 2)
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[0])
						value := strings.TrimSpace(parts[1])

						if strings.ToLower(key) == "subject" {
							info.Subject = value
						} else {
							info.Headers[key] = value
						}
					}
				}
				continue
			} else if strings.TrimSpace(line) == "" {

				headerFinished = true
				continue
			} else {

				headerFinished = true
				contentLines = append(contentLines, line)
			}
		} else {

			contentLines = append(contentLines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read template file: %v", err)
	}

	info.Content = strings.Join(contentLines, "\n")
	return info, nil
}

func (mrs *MessageRenderService) ParseTemplateBytes(templateBytes []byte) (*TemplateInfo, error) {
	content := string(templateBytes)
	lines := strings.Split(content, "\n")

	info := &TemplateInfo{
		Headers: make(map[string]string),
	}

	var contentLines []string
	headerFinished := false

	for _, line := range lines {
		if !headerFinished {

			if strings.HasPrefix(line, "#") {

				headerLine := strings.TrimPrefix(line, "#")
				headerLine = strings.TrimSpace(headerLine)

				if headerLine != "" {
					parts := strings.SplitN(headerLine, ":", 2)
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[0])
						value := strings.TrimSpace(parts[1])

						if strings.ToLower(key) == "subject" {
							info.Subject = value
						} else {
							info.Headers[key] = value
						}
					}
				}
				continue
			} else if strings.TrimSpace(line) == "" {

				headerFinished = true
				continue
			} else {

				headerFinished = true
				contentLines = append(contentLines, line)
			}
		} else {

			contentLines = append(contentLines, line)
		}
	}

	info.Content = strings.Join(contentLines, "\n")
	return info, nil
}

func (mrs *MessageRenderService) RenderTemplate(templateInfo *TemplateInfo, templateVars map[string]interface{}) (subject, content string, err error) {

	tmpl, err := template.New("content").Parse(templateInfo.Content)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse template content: %v", err)
	}

	var contentBuf strings.Builder
	if err := tmpl.Execute(&contentBuf, templateVars); err != nil {
		return "", "", fmt.Errorf("failed to execute template: %v", err)
	}

	renderedSubject := templateInfo.Subject
	if renderedSubject != "" {
		subjectTmpl, err := template.New("subject").Parse(templateInfo.Subject)
		if err != nil {
			return "", "", fmt.Errorf("failed to parse subject template: %v", err)
		}

		var subjectBuf strings.Builder
		if err := subjectTmpl.Execute(&subjectBuf, templateVars); err != nil {
			return "", "", fmt.Errorf("failed to execute subject template: %v", err)
		}
		renderedSubject = subjectBuf.String()
	}

	return renderedSubject, contentBuf.String(), nil
}

func (mrs *MessageRenderService) Render(ctx context.Context, templateBytes []byte, data map[string]interface{}) (types.MessageRenderResult, error) {

	templateInfo, err := mrs.ParseTemplateBytes(templateBytes)
	if err != nil {
		return nil, err
	}

	subject, content, err := mrs.RenderTemplate(templateInfo, data)
	if err != nil {
		return nil, err
	}

	messageType := "email"

	result := &types.FileTemplateResult{
		Type:    messageType,
		Subject: &subject,
		Body:    content,
	}

	return result, nil
}
