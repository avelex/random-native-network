package dkg

import "log"

type Logger struct {
}

func (l *Logger) Info(keyvals ...interface{})  { log.Println(keyvals...) }
func (l *Logger) Error(keyvals ...interface{}) { log.Printf("ERROR: %v\n", keyvals) }
