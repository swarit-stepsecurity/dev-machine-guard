package telemetry

import (
	"strings"

	"github.com/google/uuid"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// wslGuestNamespace namespaces the derived guest device ids. A fixed namespace
// keeps derivation stable across agent versions — change it and every WSL
// distro in every fleet becomes a new device.
var wslGuestNamespace = uuid.MustParse("6f2c1f8e-3b6d-5a4e-9c1d-7f5a2b8e0d31")

// wslGuestFromConfig returns the guest block when this run was triggered inside
// a WSL distro. Both values are required: a host id without a distro id (or the
// reverse) cannot identify anything, so a partial pair is treated as "not a
// guest" rather than half-identified.
func wslGuestFromConfig(cfg *cli.Config) *model.WSLGuest {
	if cfg == nil {
		return nil
	}
	host := strings.TrimSpace(cfg.WSLHostSerial)
	distro := strings.TrimSpace(cfg.WSLDistroID)
	if host == "" || distro == "" {
		return nil
	}
	return &model.WSLGuest{HostDeviceID: host, DistroID: distro}
}

// wslGuestDeviceID derives a distro's device id from its host serial and distro
// GUID. Deterministic, so re-scans converge on one record instead of breeding
// rows, and unique per (host, distro) so distros on one host never collide —
// which they would if we fell back to the hostname they all share.
//
// The backend does not recompute this; it pairs on distro_id. So the value only
// has to be stable and unique, not verifiable.
func wslGuestDeviceID(hostSerial, distroID string) string {
	return uuid.NewSHA1(wslGuestNamespace,
		[]byte(strings.ToLower(hostSerial+"|"+distroID))).String()
}
