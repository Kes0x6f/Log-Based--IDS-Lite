package alert

import (
	"fmt"
	"time"
)

func GenerateID() string {
	return fmt.Sprintf("ALT-%d", time.Now().UnixNano())
}
