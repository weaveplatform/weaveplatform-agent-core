package main

import "os"

// forwardSignals is empty: Windows has no SIGHUP, and the SCM has no reload
// control to translate. weavectl reload reaches core directly.
var forwardSignals []os.Signal
