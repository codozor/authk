//go:build !unix

package agent

import "os"

// ownedByCurrentUser is not checked on Windows: the socket lives in the user profile.
func ownedByCurrentUser(os.FileInfo) bool { return true }
