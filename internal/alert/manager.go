package alert

import (
	"log"

	"github.com/Kes0x6f/Log-Based--IDS/internal/database"
	"github.com/Kes0x6f/Log-Based--IDS/internal/model"
)

type Manager struct {
	AlertRepo *database.AlertRepository
}

func (m *Manager) Start(input <-chan *model.Alert) {
	for alert := range input {

		if alert.IsUpdate {
			err := m.AlertRepo.UpdateEventCount(alert.OriginalAlertID, alert.EventCount)
			if err != nil {
				log.Println("Update alert count error:", err)
			}
			continue
		}

		err := m.AlertRepo.Insert(alert)
		if err != nil {
			log.Println("Insert alert error:", err)
			continue
		}

		log.Println("ALERT:", alert.Message)
	}
}
