package main

import (
	"github.com/sirupsen/logrus"
	"os"
	"time"
)

func init() {
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.ErrorLevel)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
	})
}
