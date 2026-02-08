package config


func InitConfig(envName ...string) {
	var env string
	if len(envName) > 0 {
		env = envName[0]
	} else {
		env = ".env"
	}

	initEnv(env)
	initSession()
	initVite()
	initRateLimit()

}
