package helper

type LogStruct struct {
	TimeStamp       string `json:"@timestamp"`
	Version         string `json:"version"`
	Level           string `json:"level"`
	LevelValue      int    `json:"level_value"`
	StatusCode      string `json:"statusCode"`
	PayLoad         string `json:"pay_load"`
	Message         string `json:"message"`
	LoggerName      string `json:"logger_name"`
	AppName         string `json:"app_name"`
	Path            string `json:"path"`
	Method          string `json:"method"`
	CorrelationId   string `json:"X-Correlation-Id"`
	IdentityAgent   string `json:"Identity-Agent"`
	ResponseTime    string `json:"X-Response-Time"`
	ApplicationHost string `json:"X-Application-Host"`
	ForwardedFor    string `json:"X-Forwarded-For"`
}
