//go:build darwin

package update

// launchDetached runs c in a new session so launchd stopping the agent's job
// does not take the installer with it.
func launchDetached(c Command) error { return launchSetsid(c) }
