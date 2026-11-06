package infoextract

// defaultRules returns the built-in high-sensitivity ruleset.
// Callers must not mutate the returned slice.
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
	}
}
