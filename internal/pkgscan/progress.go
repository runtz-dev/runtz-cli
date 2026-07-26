package pkgscan

import "fmt"

func reportProgress(progress func(string), format string, args ...any) {
	if progress == nil {
		return
	}
	progress(fmt.Sprintf(format, args...))
}
