package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/weaveplatform/weaveplatform-agent-core/internal/store"
	"github.com/weaveplatform/weaveplatform-agent-core/internal/store/keyprotect"
)

// A core whose store cannot be opened runs degraded rather than not at all.
//
// Exiting was the old answer, and on a Windows clone made by sysprep it meant
// a crash loop with no way in: DPAPI ties store.key to the machine it was
// sealed on, the clone can never unseal it, and every restart failed the same
// way while the host channel — the one thing an operator could have reached
// the guest through — never came up. Repairing the store automatically is no
// better: deleting or moving it would throw away an identity, a policy cache
// and an offline queue on what might be a transient fault, and would hide from
// the operator that the image was cloned without `weave seal`.
//
// So core comes up with the channel, the control socket and the modules, and
// refuses exactly what needs the store, by name, until an operator acts.

// openStore opens core's encrypted store. A seam for the degraded-start tests.
var openStore = func(dir string) (*store.Store, error) {
	return store.Open(dir, keyprotect.New())
}

// degradedRepeat is how often the degraded ERROR is logged again: often
// enough that whoever reads the log next sees it, rarely enough not to bury
// everything else.
var degradedRepeat = 10 * time.Minute

// degradedFeatures are what a core without its store does without. Modules
// see their store calls fail Unavailable, WhoAmI fail Unavailable and
// queue_offline sends fail; the policy file still applies, without the cached
// copy behind it; channel manifests are refused.
var degradedFeatures = []string{
	"store", "identity", "policy-cache", "offline-queue", "channel-installs",
}

// degradedReason is the one message an operator needs: what is wrong, the
// likely cause and the fix.
func degradedReason(stateDir string, err error) string {
	cause := "the store files are unreadable or damaged"
	if errors.Is(err, store.ErrUnseal) || errors.Is(err, store.ErrUndecryptable) {
		cause = "the store was sealed under a different machine or user identity — " +
			"typically a VM cloned or sysprepped from a template that was not prepared with `weave seal`"
	}
	return fmt.Sprintf("core is running degraded: its encrypted store cannot be used (%v). "+
		"Likely cause: %s. Identity, module storage, the cached policy, the offline queue "+
		"and channel installs are disabled; the host channel and modules still run. "+
		"Fix: stop the weave service, delete store.key and store.db from %s "+
		"(keep manifest.sequence), then start it again — core creates a new store and a new "+
		"device identity", err, cause, stateDir)
}

// reportDegraded logs the degraded ERROR now, and again every degradedRepeat
// until ctx ends.
func reportDegraded(ctx context.Context, log *slog.Logger, reason string, err error) {
	log.Error(reason, "err", err)
	go func() {
		t := time.NewTicker(degradedRepeat)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Error(reason, "err", err)
			}
		}
	}()
}
