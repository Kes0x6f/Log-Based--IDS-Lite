package collector

import (
	"bufio"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Kes0x6f/Log-Based--IDS/internal/stream"
	"github.com/fsnotify/fsnotify"
)

type FileCollector struct {
	FilePath    string
	Source      string
	Broadcaster *stream.Broadcaster
}

type RawLog struct {
	Source  string //"auth", "syslog"
	Message string
}

func (fc *FileCollector) Start(out chan<- RawLog) error {
	file, reader, err := openFile(fc.FilePath)
	if err != nil {
		return err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	watcher.Add(filepath.Dir(fc.FilePath))
	//Partial line changes
	buffer := ""

	go func() {
		for {
			select {

			case event := <-watcher.Events:

				if filepath.Base(event.Name) != filepath.Base(fc.FilePath) {
					continue
				}

				//Handles log rotation
				if event.Op&(fsnotify.Rename|fsnotify.Create) != 0 {
					file.Close()
					file, reader, err = openFile(fc.FilePath)
					if err != nil {
						log.Println("reopen error:", err)
					}
					continue
				}

				//Line Handling
				if event.Op&fsnotify.Write == fsnotify.Write {
					for {
						chunk, err := reader.ReadString('\n')
						buffer += chunk

						if err != nil {
							break
						}

						lines := strings.Split(buffer, "\n")

						for i := 0; i < len(lines)-1; i++ {
							out <- RawLog{
								Source:  fc.Source,
								Message: lines[i],
							}

							if fc.Broadcaster != nil {
								fc.Broadcaster.Publish(lines[i])
							}
						}

						buffer = lines[len(lines)-1]

					}
				}

			case err := <-watcher.Errors:
				log.Println("watch error:", err)

			}
		}
	}()

	return nil
}

func openFile(path string) (*os.File, *bufio.Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}

	f.Seek(0, io.SeekEnd)
	return f, bufio.NewReader(f), nil
}
