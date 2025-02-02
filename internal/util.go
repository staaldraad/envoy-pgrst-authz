package internal

import (
	"fmt"
	"io"
	"os"

	"github.com/fsnotify/fsnotify"
	"github.com/staaldraad/envoy-pgrst-auth/internal/policyengine"
)

func readFile(path string) ([]byte, error) {
	policyFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer policyFile.Close()

	rawPolicy, err := io.ReadAll(policyFile)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	return rawPolicy, nil
}

func WatchFile(path string, policyEngine policyengine.PolicyEngine) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	//
	done := make(chan bool)

	//
	go func() {
		for {
			select {
			// watch for events
			case event := <-watcher.Events:
				if event.Op.String() == "WRITE" {
					// reload the file
					if rawPolicy, err := readFile(path); err != nil {
						fmt.Println(err)
					} else {
						policyEngine.LoadPolicy(rawPolicy)
					}
				}
				// watch for errors
			case err := <-watcher.Errors:
				fmt.Println("ERROR", err)
			}
		}
	}()

	// out of the box fsnotify can watch a single file, or a single directory
	if err := watcher.Add(path); err != nil {
		fmt.Println("ERROR", err)
	}

	// initial load
	if rawPolicy, err := readFile(path); err != nil {
		return err
	} else {
		policyEngine.LoadPolicy(rawPolicy)
	}
	<-done
	return nil
}
