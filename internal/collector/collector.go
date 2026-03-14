package collector

type Collector interface {
	Start(out chan<- string) error
}
