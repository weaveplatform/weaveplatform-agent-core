package main

import "context"

// notifyReload has no signal to listen for: Windows has no SIGHUP. weavectl
// reload and the periodic rescan reach the same reload.
func notifyReload(context.Context) <-chan struct{} { return nil }
