package helper

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"time"
	configuration "walls-identity-service/internal/core/helper/configuration-helper"
	errorhelper "walls-identity-service/internal/core/helper/error-helper"

	"github.com/gin-gonic/gin"
)

func InitializeLog() {
	config := configuration.ServiceConfiguration
	logDir := config.LogDir
	_ = os.Mkdir(logDir, os.ModePerm)

	f, err := os.OpenFile(logDir+config.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		LogEvent("ERROR", errorhelper.ErrorMessage(errorhelper.LogError, err.Error()))
		log.Fatalf("error opening file: %v", err)
	}
	log.SetFlags(0)
	log.SetOutput(f)
}

type BodyLogWriter struct {
	gin.ResponseWriter
	Body *bytes.Buffer
}

func (w BodyLogWriter) Write(b []byte) (int, error) {
	w.Body.Write(b)
	return w.ResponseWriter.Write(b)
}

func LogEvent(level string, message interface{}) {

	data, err := json.Marshal(struct {
		TimeStamp string      `json:"@timestamp"`
		Level     string      `json:"level"`
		AppName   string      `json:"app_name"`
		Message   interface{} `json:"message"`
	}{TimeStamp: time.Now().Format(time.RFC3339),
		AppName: configuration.ServiceConfiguration.ServiceName,
		Message: message,
		Level:   level,
	})

	if err != nil {
		LogEvent("ERROR", errorhelper.ErrorMessage(errorhelper.LogError, err.Error()))
		log.Fatal(err)
	}
	log.Printf("%s\n", data)

}
