package context

type DetectionContext struct {
	// Intentionally shared state between sudo rules (see sudo_shared.go)
	SudoShared *SharedSudoContext

	// Private rule state. Each rule stores and retrieves its own
	// state by a unique key. Nothing outside that rule reads this.
	private map[string]any
}

func NewDetectionContext() *DetectionContext {
	return &DetectionContext{
		SudoShared: NewSharedSudoContext(),
		private:    make(map[string]any),
	}
}

func (ctx *DetectionContext) GetPrivate(key string) (any, bool) {
	v, ok := ctx.private[key]
	return v, ok
}

func (ctx *DetectionContext) SetPrivate(key string, val any) {
	ctx.private[key] = val
}
