package utility

import (
	"strconv"
	"strings"
	"sync"
)

// once-computed cache for CURRENT_CONTEXT_MAX_ITEMS to avoid repeated file I/O and parsing in hot paths
var (
	contextMaxItemsOnce   sync.Once
	contextMaxItemsCached int
)

// getContextMaxItems reads CURRENT_CONTEXT_MAX_ITEMS from config, defaults to 8, and clamps to [1, 50].
func getContextMaxItems() int {
	const (
		defaultValue = 8
		minValue     = 1
		maxValue     = 50
	)

	contextMaxItemsOnce.Do(func() {
		// Default first
		contextMaxItemsCached = defaultValue

		cfg, err := LoadConfig()
		if err != nil {
			return
		}

		v := strings.TrimSpace(cfg["CURRENT_CONTEXT_MAX_ITEMS"])
		if v == "" {
			return
		}

		n, err := strconv.Atoi(v)
		if err != nil {
			return
		}

		if n < minValue {
			contextMaxItemsCached = minValue
			return
		}
		if n > maxValue {
			contextMaxItemsCached = maxValue
			return
		}
		contextMaxItemsCached = n
	})
	return contextMaxItemsCached
}
