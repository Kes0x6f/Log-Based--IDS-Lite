package authEngine

import (
	"fmt"

	sshdetection "github.com/Kes0x6f/Log-Based--IDS/internal/detection/auth_detection"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

func AuthEngine(events []*model.NormalizedEvent) []string {

	state := sshdetection.NewSSHDetectionState()
	var detectedAlerts []string
	//DETECTION START
	fmt.Print("detection start")
	for _, event := range events {
		alerts := state.Process(event)

		for _, alert := range alerts {
			detectedAlerts = append(detectedAlerts, "ALERT:"+alert)
		}
	}
	return detectedAlerts
}
