package storage

import "golang.org/x/sys/unix"

func cloneFile(srcPath, dstPath string) error {
	return unix.Clonefile(srcPath, dstPath, 0)
}
