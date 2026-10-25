package infoextract

// defaultRules returns the built-in ruleset (20+ rules covering high/medium/low
// sensitivity). Callers must not mutate the returned slice.
func defaultRules() []Rule {
	return []Rule{
		// ── High sensitivity ────────────────────────────────────────────────
		{
			Name:        "aws_access_key",
			Pattern:     `AKIA[0-9A-Z]{16}`,
			Color:       "red",
			Scope:       "all",
			Sensitivity: "high",
			Triggers:    []string{"AKIA"},
		},
		{
			Name:        "aws_secret_key",
			Pattern:     `aws_secret[^=]*=\s*['"]?([A-Za-z0-9/+=]{40})`,
			Color:       "red",
			Scope:       "all",
			Sensitivity: "high",
			Triggers:    []string{"aws_secret", "AWS_SECRET"},
		},
		{
			Name:        "private_key",
			Pattern:     `-----BEGIN [A-Z ]+PRIVATE KEY-----`,
			Color:       "red",
			Scope:       "all",
			Sensitivity: "high",
			Triggers:    []string{"-----BEGIN"},
		},
		{
			Name:        "jwt_token",
			Pattern:     `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`,
			Color:       "red",
			Scope:       "all",
			Sensitivity: "high",
			Triggers:    []string{"eyJ"},
		},
		{
			Name:        "github_token",
			Pattern:     `ghp_[A-Za-z0-9]{36}`,
			Color:       "red",
			Scope:       "all",
			Sensitivity: "high",
			Triggers:    []string{"ghp_", "github_token"},
		},
		{
			Name:        "slack_token",
			Pattern:     `xox[bpao]-[0-9A-Za-z\-]+`,
			Color:       "red",
			Scope:       "all",
			Sensitivity: "high",
			Triggers:    []string{"xoxb-", "xoxp-", "xoxa-"},
		},
		{
			Name:        "stripe_key",
			Pattern:     `sk_(live|test)_[A-Za-z0-9]{24,}`,
			Color:       "red",
			Scope:       "all",
			Sensitivity: "high",
			Triggers:    []string{"sk_live_", "sk_test_"},
		},
		{
			Name:        "aliyun_access_key",
			Pattern:     `LTAI[0-9A-Za-z]{12,20}`,
			Color:       "red",
			Scope:       "all",
			Sensitivity: "high",
			Triggers:    []string{"LTAI"},
		},
		{
			Name:        "tencent_secret_id",
			Pattern:     `AKID[0-9A-Za-z]{13,40}`,
			Color:       "red",
			Scope:       "all",
			Sensitivity: "high",
			Triggers:    []string{"AKID"},
		},
		{
			Name:        "database_url",
			Pattern:     `(mysql|postgres|mongodb|redis)://[^'"\s]+`,
			Color:       "red",
			Scope:       "all",
			Sensitivity: "high",
			Triggers:    []string{"mysql://", "postgres://", "mongodb://", "redis://"},
		},
		{
			Name:        "access_token",
			Pattern:     `access_token['"\s:=]+([A-Za-z0-9._\-]{20,})`,
			Color:       "red",
			Scope:       "all",
			Sensitivity: "high",
			Triggers:    []string{"access_token", "accessToken", "ACCESS_TOKEN"},
		},
		{
			Name:        "bearer_token",
			Pattern:     `Bearer\s+([A-Za-z0-9._\-]+)`,
			Color:       "red",
			Scope:       "all",
			Sensitivity: "high",
			Triggers:    []string{"Bearer "},
		},
		{
			Name:        "api_key",
			Pattern:     `api[_-]?key['"\s:=]+([A-Za-z0-9\-_]{16,64})`,
			Color:       "red",
			Scope:       "all",
			Sensitivity: "high",
			Triggers:    []string{"api_key", "apiKey", "API_KEY", "x-api-key"},
		},

		// ── Medium sensitivity ───────────────────────────────────────────────
		{
			Name:        "password_field",
			Pattern:     `pass(?:word|wd)?['"\s:=]+([^\s'"<>&]{6,50})`,
			Color:       "orange",
			Scope:       "all",
			Sensitivity: "medium",
			Triggers:    []string{"password", "passwd", "pwd"},
		},
		{
			// fallback: no triggers, runs unconditionally
			Name:        "internal_ip",
			Pattern:     `(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)`,
			Color:       "orange",
			Scope:       "all",
			Sensitivity: "medium",
			Triggers:    nil,
		},
		{
			// fallback
			Name:        "id_card_cn",
			Pattern:     `\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[012])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`,
			Color:       "orange",
			Scope:       "all",
			Sensitivity: "medium",
			Triggers:    nil,
		},
		{
			Name:        "wechat_appid",
			Pattern:     `(?i)appid['\s:=]+([a-z0-9]{16,18})`,
			Color:       "orange",
			Scope:       "all",
			Sensitivity: "medium",
			Triggers:    []string{"appid", "AppID", "wx"},
		},

		// ── Low sensitivity ──────────────────────────────────────────────────
		{
			// fallback
			Name:        "email",
			Pattern:     `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
			Color:       "blue",
			Scope:       "all",
			Sensitivity: "low",
			Triggers:    nil,
		},
		{
			// fallback
			Name:        "ipv4",
			Pattern:     `\b(?:\d{1,3}\.){3}\d{1,3}\b`,
			Color:       "gray",
			Scope:       "all",
			Sensitivity: "low",
			Triggers:    nil,
		},
		{
			// fallback
			Name:        "url",
			Pattern:     `https?://[^\s'"<>]{10,200}`,
			Color:       "gray",
			Scope:       "all",
			Sensitivity: "low",
			Triggers:    nil,
		},
		{
			// fallback
			Name:        "phone_cn",
			Pattern:     `\b1[3-9]\d{9}\b`,
			Color:       "gray",
			Scope:       "all",
			Sensitivity: "low",
			Triggers:    nil,
		},
		{
			Name:        "linkfinder",
			Pattern:     `(?:"|')(/(?:api|v[0-9]+|graphql)/[a-zA-Z0-9_/\-?=&]{1,200})(?:"|')`,
			Color:       "blue",
			Scope:       "body",
			Sensitivity: "low",
			Triggers:    []string{"/api/", "/v1/", "/v2/", "/graphql"},
			Category:    "special",
		},
	}
}
