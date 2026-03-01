package context

type DetectionContext struct {
	SSH *SSHState
}

func NewDetectionContext() *DetectionContext {
	return &DetectionContext{
		SSH: NewSSHState(),
	}
}
