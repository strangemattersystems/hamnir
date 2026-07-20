package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// storeDevice seeds a pending device authorization and returns its codes.
func storeDevice(t *testing.T, st *Storage, clientID string) (deviceCode, userCode string) {
	t.Helper()
	deviceCode, userCode = "dev_"+t.Name(), "BCDF-GHJK"
	if err := st.StoreDeviceAuthorization(context.Background(), clientID, deviceCode, userCode, time.Now().Add(5*time.Minute), []string{"openid"}); err != nil {
		t.Fatal(err)
	}
	return deviceCode, userCode
}

func TestStorage_DeviceAuthorization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("pending state round-trips", func(t *testing.T) {
		t.Parallel()

		st := newTestStorage(t)
		dc, _ := storeDevice(t, st, "cli")
		state, err := st.GetDeviceAuthorizatonState(ctx, "cli", dc)
		if err != nil {
			t.Fatal(err)
		}
		if state.Done || state.Denied || state.ClientID != "cli" {
			t.Fatalf("unexpected pending state: %+v", state)
		}
	})

	t.Run("approve completes the state", func(t *testing.T) {
		t.Parallel()

		st := newTestStorage(t)
		dc, uc := storeDevice(t, st, "cli")
		if err := st.ApproveDevice(uc, "usr_alice"); err != nil {
			t.Fatal(err)
		}
		state, err := st.GetDeviceAuthorizatonState(ctx, "cli", dc)
		if err != nil {
			t.Fatal(err)
		}
		if !state.Done || state.Subject != "usr_alice" || state.AuthTime.IsZero() {
			t.Fatalf("approve did not complete the state: %+v", state)
		}
		if len(state.AMR) != 1 || state.AMR[0] != "pwd" {
			t.Fatalf("AMR = %v, want [pwd]", state.AMR)
		}
	})

	t.Run("user code matching is forgiving", func(t *testing.T) {
		t.Parallel()

		st := newTestStorage(t)
		_, _ = storeDevice(t, st, "cli") // canonical BCDF-GHJK
		if err := st.ApproveDevice(" bcdf ghjk ", "usr_alice"); err != nil {
			t.Fatalf("normalised lookup failed: %v", err)
		}
	})

	t.Run("deny marks the state denied", func(t *testing.T) {
		t.Parallel()

		st := newTestStorage(t)
		dc, uc := storeDevice(t, st, "cli")
		if err := st.DenyDevice(uc); err != nil {
			t.Fatal(err)
		}
		if state, _ := st.GetDeviceAuthorizatonState(ctx, "cli", dc); !state.Denied {
			t.Fatalf("expected denied state, got %+v", state)
		}
	})

	t.Run("handled codes reject a second decision", func(t *testing.T) {
		t.Parallel()

		st := newTestStorage(t)
		_, uc := storeDevice(t, st, "cli")
		if err := st.ApproveDevice(uc, "usr_alice"); err != nil {
			t.Fatal(err)
		}
		if err := st.DenyDevice(uc); !errors.Is(err, ErrDeviceCodeHandled) {
			t.Fatalf("err = %v, want ErrDeviceCodeHandled", err)
		}
	})

	t.Run("unknown user code", func(t *testing.T) {
		t.Parallel()

		st := newTestStorage(t)
		if err := st.LookupDeviceUserCode("XXXX-XXXX"); !errors.Is(err, ErrDeviceCodeNotFound) {
			t.Fatalf("err = %v, want ErrDeviceCodeNotFound", err)
		}
	})

	t.Run("expired code rejected for approval", func(t *testing.T) {
		t.Parallel()

		st := newTestStorage(t)
		if err := st.StoreDeviceAuthorization(ctx, "cli", "dev_x", "MNPQ-RSTV", time.Now().Add(-time.Minute), nil); err != nil {
			t.Fatal(err)
		}
		if err := st.ApproveDevice("MNPQ-RSTV", "usr_alice"); !errors.Is(err, ErrDeviceCodeExpired) {
			t.Fatalf("err = %v, want ErrDeviceCodeExpired", err)
		}
	})

	t.Run("duplicate user code reported to op", func(t *testing.T) {
		t.Parallel()

		st := newTestStorage(t)
		_, uc := storeDevice(t, st, "cli")
		err := st.StoreDeviceAuthorization(ctx, "cli", "dev_other", uc, time.Now().Add(time.Minute), nil)
		if !errors.Is(err, op.ErrDuplicateUserCode) {
			t.Fatalf("err = %v, want op.ErrDuplicateUserCode", err)
		}
	})

	t.Run("wrong client cannot read the state", func(t *testing.T) {
		t.Parallel()

		st := newTestStorage(t)
		dc, _ := storeDevice(t, st, "mine")
		if _, err := st.GetDeviceAuthorizatonState(ctx, "other", dc); !errors.Is(err, ErrDeviceCodeNotFound) {
			t.Fatalf("err = %v, want ErrDeviceCodeNotFound for a client mismatch", err)
		}
	})

	t.Run("expired requests are pruned on store", func(t *testing.T) {
		t.Parallel()

		st := newTestStorage(t)
		if err := st.StoreDeviceAuthorization(ctx, "cli", "dev_old", "WXZB-CDFG", time.Now().Add(-time.Hour), nil); err != nil {
			t.Fatal(err)
		}
		_, _ = storeDevice(t, st, "cli") // triggers the prune
		if err := st.LookupDeviceUserCode("WXZB-CDFG"); !errors.Is(err, ErrDeviceCodeNotFound) {
			t.Fatalf("expired request survived the prune: %v", err)
		}
	})

	t.Run("just-expired requests survive the prune for their outcome", func(t *testing.T) {
		t.Parallel()

		st := newTestStorage(t)
		if err := st.StoreDeviceAuthorization(ctx, "cli", "dev_edge", "WXZB-CDFG", time.Now().Add(-time.Second), nil); err != nil {
			t.Fatal(err)
		}
		_, _ = storeDevice(t, st, "cli") // triggers the prune
		// Expired for approval, but still present: the state must remain
		// readable so op reports expired_token rather than access_denied.
		if err := st.LookupDeviceUserCode("WXZB-CDFG"); !errors.Is(err, ErrDeviceCodeExpired) {
			t.Fatalf("err = %v, want ErrDeviceCodeExpired (present but expired)", err)
		}
		if _, err := st.GetDeviceAuthorizatonState(ctx, "cli", "dev_edge"); err != nil {
			t.Fatalf("state must stay readable within the grace: %v", err)
		}
	})

	t.Run("approval decided at the deadline survives for the final poll", func(t *testing.T) {
		t.Parallel()

		st := newTestStorage(t)
		dc, uc := storeDevice(t, st, "cli")
		if err := st.ApproveDevice(uc, "usr_alice"); err != nil {
			t.Fatal(err)
		}
		// Rewind the expiry past the deadline but inside the grace, then
		// trigger a prune: the approved outcome must still be pollable.
		st.mu.Lock()
		st.deviceRequests[dc].expires = time.Now().Add(-time.Second)
		st.mu.Unlock()
		if err := st.StoreDeviceAuthorization(ctx, "other", "dev_trigger", "MNPQ-RSTV", time.Now().Add(time.Minute), nil); err != nil {
			t.Fatal(err)
		}
		state, err := st.GetDeviceAuthorizatonState(ctx, "cli", dc)
		if err != nil || !state.Done || state.Subject != "usr_alice" {
			t.Fatalf("approved outcome lost to the prune: state=%+v err=%v", state, err)
		}
	})
}
