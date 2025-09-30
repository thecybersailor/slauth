package consts

var BuildinTemplates = map[string]map[string][]byte{
	"email": {
		"change-email": []byte(`# Subject: Confirm Change of Email

<h2>Confirm Change of Email</h2>

<p>Follow this link to confirm the update of your email from {{ .Email }} to {{ .NewEmail }}:</p>
<p><a href="{{ .ConfirmationURL }}">Change Email</a></p>
`),
		"confirm-signup": []byte(`# Subject: Confirm your signup

<h2>Confirm your signup</h2>

<p>Follow this link to confirm your user:</p>
<p><a href="{{ .ConfirmationURL }}">Confirm your mail</a></p>
`),
		"invite-user": []byte(`# Subject: You have been invited

<h2>You have been invited</h2>

<p>You have been invited to create a user on {{ .SiteURL }}. Follow this link to accept the invite:</p>
<p><a href="{{ .ConfirmationURL }}">Accept the invite</a></p>
`),
		"magic-link": []byte(`# Subject: Magic Link

<h2>Magic Link</h2>

<p>Follow this link to login:</p>
<p><a href="{{ .ConfirmationURL }}">Log In</a></p>
`),
		"reset-password": []byte(`# Subject: Reset Password

<h2>Reset Password</h2>

<p>Follow this link to reset the password for your user:</p>
<p><a href="{{ .ConfirmationURL }}">Reset Password</a></p>
`),
		"verification-code": []byte(`# Subject: Your verification code

<h2>Your verification code</h2>

<p>Your 6-digit verification code is:</p>
<h1 style="font-size: 32px; color: #007bff; letter-spacing: 4px;">{{ .Code }}</h1>
<p>This code will expire in 10 minutes.</p>

<p>If you didn't request this code, please ignore this email.</p>
`),
	},
	"sms": {
		"reauthentication": []byte(`# Subject: Reauthentication Code

<h2>Confirm reauthentication</h2>

<p>Enter the code: {{ .Token }}</p>
`),
		"verification-code": []byte(`# Subject: SMS Verification Code

Your verification code is: {{ .Code }}

This code will expire in 10 minutes. Do not share this code with anyone.
`),
	},
}
