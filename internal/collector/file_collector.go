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
	// Stats is optional; when non-nil, every emitted line is counted.
	Stats *SourceStats
}

type RawLog struct {
	Source  string // "auth", "ufw", "kern", "audit", "apache2", "nginx"
	Message string
}

func (fc *FileCollector) Start(out chan<- RawLog) error {
	file, reader, err := openFile(fc.FilePath)
	if err != nil {
		if fc.Stats != nil {
			fc.Stats.SetWatcherAlive(fc.Source, false)
		}
		return err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	watcher.Add(filepath.Dir(fc.FilePath))

	if fc.Stats != nil {
		fc.Stats.SetWatcherAlive(fc.Source, true)
	}

	// Partial line buffer — carries incomplete lines across read iterations.
	buffer := ""

	go func() {
		for {
			select {

			case event := <-watcher.Events:

				if filepath.Base(event.Name) != filepath.Base(fc.FilePath) {
					continue
				}

				// Handle log rotation: file renamed then re-created.
				if event.Op&(fsnotify.Rename|fsnotify.Create) != 0 {
					file.Close()
					file, reader, err = openFile(fc.FilePath)
					if err != nil {
						log.Println("reopen error:", err)
						if fc.Stats != nil {
							fc.Stats.SetWatcherAlive(fc.Source, false)
						}
					} else if fc.Stats != nil {
						fc.Stats.SetWatcherAlive(fc.Source, true)
					}
					continue
				}

				if event.Op&fsnotify.Write == fsnotify.Write {
					for {
						chunk, err := reader.ReadString('\n')
						buffer += chunk

						if err != nil {
							break
						}

						lines := strings.Split(buffer, "\n")

						for i := 0; i < len(lines)-1; i++ {
							line := lines[i]

							out <- RawLog{
								Source:  fc.Source,
								Message: line,
							}

							if fc.Stats != nil {
								fc.Stats.RecordLine(fc.Source)
							}

							if fc.Broadcaster != nil {
								// Change 3: pass source tag alongside the line so the
								// SSE stream and live.html can colour by source.
								fc.Broadcaster.Publish(fc.Source, line)
							}
						}

						buffer = lines[len(lines)-1]
					}
				}

			case watchErr := <-watcher.Errors:
				log.Println("watch error:", watchErr)
				if fc.Stats != nil {
					fc.Stats.SetWatcherAlive(fc.Source, false)
				}
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
