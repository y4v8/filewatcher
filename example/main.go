package main

import (
	"github.com/y4v8/filewatcher"
	"github.com/y4v8/filewatcher/win"
	"log"
	"strings"
)

func main() {
	events := make(chan filewatcher.Event, 32)

	w, err := filewatcher.NewWatcher(events)
	if err != nil {
		log.Fatal(err)
	}
	w.Add(`C:\`)
	go w.Start()

	for event := range events {
		log.Println(event.Name, reasonNames(event.Reason))
	}
}

func reasonNames(mask win.UsnReason) string {
	var res []string
	for r, name := range win.UsnReasonNames {
		if r&mask != 0 {
			res = append(res, name)
		}
	}
	return strings.Join(res, " ")
}
