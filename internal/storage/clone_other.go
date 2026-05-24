//go:build !darwin

package storage

import "errors"

func cloneFile(_, _ string) error {
	return errors.New("filesystem clone is not available on this platform")
}
