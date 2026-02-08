package config

// RateLimitConfig holds all rate-limiter related configuration
type RateLimitConfig struct {
	// Enabled toggles the rate limiter on/off globally
	Enabled bool

	// Store is the backing store type: "memory" or "redis"
	Store string

	// RedisPrefix is the key prefix for all rate-limit keys in Redis
	RedisPrefix string

	// Redis holds the Redis connection config (shared with session if desired)
	Redis *RedisConfig

	// TrustedProxies is a list of CIDR ranges or IPs that are trusted reverse proxies.
	// X-Forwarded-For / X-Real-IP headers are only honoured from these peers.
	TrustedProxies []string

	// DefaultResponseFormat is the content type for 429 responses: "json" or "html"
	DefaultResponseFormat string

	// LogTableEnabled controls whether denied requests are logged to the database
	LogTableEnabled bool

	// --- Default policy values (used when no per-route policy is set) ---
	DefaultLimit  int
	DefaultWindow int // seconds
	DefaultBurst  int
}

var RateLimit *RateLimitConfig

func initRateLimit() {
	proxyStr := GetEnv("RATE_LIMIT_TRUSTED_PROXIES", "").(string)
	var proxies []string
	if proxyStr != "" {
		for _, p := range splitCSV(proxyStr) {
			proxies = append(proxies, p)
		}
	}

	RateLimit = &RateLimitConfig{
		Enabled:               GetEnv("RATE_LIMIT_ENABLED", true).(bool),
		Store:                 GetEnv("RATE_LIMIT_STORE", "memory").(string),
		RedisPrefix:           GetEnv("RATE_LIMIT_REDIS_PREFIX", "gohst:rl:").(string),
		DefaultResponseFormat: GetEnv("RATE_LIMIT_RESPONSE_FORMAT", "json").(string),
		LogTableEnabled:       GetEnv("RATE_LIMIT_LOG_TABLE", false).(bool),
		DefaultLimit:          GetEnv("RATE_LIMIT_DEFAULT_LIMIT", 300).(int),
		DefaultWindow:         GetEnv("RATE_LIMIT_DEFAULT_WINDOW", 60).(int),
		DefaultBurst:          GetEnv("RATE_LIMIT_DEFAULT_BURST", 60).(int),
		TrustedProxies:        proxies,
		Redis: &RedisConfig{
			DB:       GetEnv("RATE_LIMIT_REDIS_DB", 0).(int),
			Host:     GetEnv("RATE_LIMIT_REDIS_HOST", GetEnv("SESSION_REDIS_HOST", "localhost").(string)).(string),
			Password: GetEnv("RATE_LIMIT_REDIS_PASSWORD", GetEnv("SESSION_REDIS_PASSWORD", "").(string)).(string),
			Port:     GetEnv("RATE_LIMIT_REDIS_PORT", GetEnv("SESSION_REDIS_PORT", 6379).(int)).(int),
		},
	}
}

// splitCSV is a small helper to split a comma-separated string
func splitCSV(s string) []string {
	var result []string
	for _, part := range splitBy(s, ',') {
		trimmed := trimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func splitBy(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
