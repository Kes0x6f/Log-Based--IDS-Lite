package collector

import (
	"bufio"
	"io"
	"log"
	"os"

	"github.com/Kes0x6f/Log-Based--IDS/internal/stream"
	"github.com/fsnotify/fsnotify"
)

type FileCollector struct {
	FilePath    string
	Broadcaster *stream.Broadcaster
}

type RawLog struct {
	Source  string
	Message string
}

func (fc *FileCollector) Start(out chan<- RawLog) error {
	file, err := os.Open(fc.FilePath)
	if err != nil {
		return err
	}

	file.Seek(0, io.SeekEnd)

	reader := bufio.NewReader(file)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	watcher.Add(fc.FilePath)

	go func() {
		for {
			select {

			case event := <-watcher.Events:

				if event.Op&fsnotify.Write == fsnotify.Write {

					for {
						line, err := reader.ReadString('\n')
						if err != nil {
							break
						}
						out <- RawLog{
							Source:  fc.FilePath,
							Message: line,
						}
						if fc.Broadcaster != nil {
							fc.Broadcaster.Publish(line)
						}
					}

				}

			case err := <-watcher.Errors:
				log.Println("watch error:", err)

			}
		}
	}()

	return nil
}
