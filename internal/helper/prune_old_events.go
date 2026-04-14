package helper

import "time"

func PruneOld(times []time.Time, now time.Time, window time.Duration) []time.Time {
	var pruned []time.Time
	for _, t := range times {
		if now.Sub(t) <= window {
			pruned = append(pruned, t)
		}
	}
	return pruned
}
