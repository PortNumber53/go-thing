package logging

import (
	"io"
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

// Setup configures logging to write to both stdout and a file and returns the file handle.
func Setup() (*os.File, error) {
	logPath := "debug.log"
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	mw := io.MultiWriter(os.Stdout, f)
	log.SetOutput(mw)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	gin.DefaultWriter = mw
	gin.DefaultErrorWriter = mw
	return f, nil
}
