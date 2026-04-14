package context

type DetectionContext struct {
	SSH  *SSHState
	Sudo *SudoState
}

func NewDetectionContext() *DetectionContext {
	return &DetectionContext{
		SSH:  NewSSHState(),
		Sudo: NewSudoState(),
	}
}
