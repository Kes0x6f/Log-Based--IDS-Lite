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

		err := m.AlertRepo.Insert(alert)
		if err != nil {
			log.Println("Insert alert error:", err)
			continue
		}

		log.Println("ALERT:", alert.Message)
	}
}
