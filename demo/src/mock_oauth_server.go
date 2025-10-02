package main

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func setupMockOAuthServer(r *gin.Engine) {
	mockGroup := r.Group("/mock-oauth")
	{
		mockGroup.GET("/authorize", handleMockOAuthAuthorize)
		mockGroup.POST("/callback-handler", handleMockOAuthCallback)
	}
}

func handleMockOAuthAuthorize(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	state := c.Query("state")
	scope := c.Query("scope")

	tmpl := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Mock OAuth - Authorization</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            margin-bottom: 20px;
        }
        .info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
            font-family: monospace;
            font-size: 14px;
        }
        .info-item {
            margin: 8px 0;
        }
        .info-label {
            color: #666;
            font-weight: bold;
        }
        .button-group {
            display: flex;
            gap: 10px;
            margin-top: 30px;
        }
        button {
            flex: 1;
            padding: 12px 24px;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-approve {
            background: #28a745;
            color: white;
        }
        .btn-approve:hover {
            background: #218838;
        }
        .btn-deny {
            background: #dc3545;
            color: white;
        }
        .btn-deny:hover {
            background: #c82333;
        }
        .user-select {
            margin: 20px 0;
        }
        .user-select label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
        }
        .user-select select {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 data-testid="mock-oauth-title">Mock OAuth Authorization</h1>
        <div class="info">
            <div class="info-item">
                <span class="info-label">Client ID:</span> {{.ClientID}}
            </div>
            <div class="info-item">
                <span class="info-label">Redirect URI:</span> {{.RedirectURI}}
            </div>
            <div class="info-item">
                <span class="info-label">State:</span> {{.State}}
            </div>
            <div class="info-item">
                <span class="info-label">Scope:</span> {{.Scope}}
            </div>
        </div>
        
        <div class="user-select">
            <label for="user">Select Mock User:</label>
            <select id="user" name="user" data-testid="mock-oauth-user-select">
                <option value="user1">Mock User 1 (user1@example.com)</option>
                <option value="user2">Mock User 2 (user2@example.com)</option>
                <option value="user3">Mock User 3 (user3@example.com)</option>
                <option value="admin">Mock Admin (admin@example.com)</option>
            </select>
        </div>

        <div class="button-group">
            <button class="btn-approve" data-testid="mock-oauth-approve" onclick="approve()">Approve</button>
            <button class="btn-deny" data-testid="mock-oauth-deny" onclick="deny()">Deny</button>
        </div>
    </div>

    <script>
        const redirectURI = "{{.RedirectURI}}";
        const state = "{{.State}}";

        function approve() {
            const user = document.getElementById('user').value;
            const code = 'mock_code_' + user + '_' + Date.now();
            const url = redirectURI + '?code=' + encodeURIComponent(code) + '&state=' + encodeURIComponent(state);
            window.location.href = url;
        }

        function deny() {
            const url = redirectURI + '?error=access_denied&state=' + encodeURIComponent(state);
            window.location.href = url;
        }
    </script>
</body>
</html>`

	t, err := template.New("authorize").Parse(tmpl)
	if err != nil {
		c.String(http.StatusInternalServerError, "Template error")
		return
	}

	data := map[string]string{
		"ClientID":    clientID,
		"RedirectURI": redirectURI,
		"State":       state,
		"Scope":       scope,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(c.Writer, data); err != nil {
		c.String(http.StatusInternalServerError, "Template execution error")
		return
	}
}

func handleMockOAuthCallback(c *gin.Context) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")

	if code == "" || redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "missing_parameters",
		})
		return
	}

	time.Sleep(500 * time.Millisecond)

	c.JSON(http.StatusOK, gin.H{
		"access_token":  fmt.Sprintf("mock_access_token_%s", code),
		"refresh_token": fmt.Sprintf("mock_refresh_token_%s", code),
		"token_type":    "Bearer",
		"expires_in":    3600,
		"id_token":      fmt.Sprintf("mock_id_token_%s", code),
	})
}
