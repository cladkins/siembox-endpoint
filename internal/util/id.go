// Package util holds small cross-cutting helpers with no external dependencies.
package util

import (
	"crypto/rand"
	"fmt"
)

// NewID returns a random RFC 4122 version-4 UUID string. Used for event ids
// without pulling in an external UUID dependency.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand should never fail; fall back to a zero-ish id rather
		// than panicking inside the agent's hot path.
		return "00000000-0000-0000-0000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
