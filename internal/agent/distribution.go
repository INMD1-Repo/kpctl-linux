package agent

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"kpctl/internal/model"
)

// RunningBuildID reads the kernel's in-memory GNU note, even after the image on disk changed.
func RunningBuildID(notes []byte) (string, error) {
	for len(notes) >= 12 {
		n, d, t := int64(binary.LittleEndian.Uint32(notes)), int64(binary.LittleEndian.Uint32(notes[4:])), binary.LittleEndian.Uint32(notes[8:])
		ds := 12 + ((n + 3) &^ 3)
		end := ds + ((d + 3) &^ 3)
		if end > int64(len(notes)) {
			break
		}
		if n == 4 && t == 3 && d == 20 && string(notes[12:16]) == "GNU\x00" {
			return hex.EncodeToString(notes[ds : ds+d]), nil
		}
		notes = notes[end:]
	}
	return "", fmt.Errorf("running kernel GNU build ID unavailable")
}

func IdentifyKernel(abi, notesPath, distroPath, versionPath string) (*model.DistributionKernel, error) {
	if distroPath == "" {
		distroPath = "/etc/os-release"
	}
	b, err := os.ReadFile(distroPath)
	if err != nil {
		return nil, err
	}
	osinfo := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		key, val, ok := strings.Cut(line, "=")
		if ok {
			osinfo[key] = strings.Trim(val, "\"'")
		}
	}
	if osinfo["ID"] == "ubuntu" {
		if model.LTSForKernel(abi) == nil {
			return nil, fmt.Errorf("unsupported Ubuntu kernel %s", abi)
		}
		return nil, nil
	}
	k := &model.DistributionKernel{Distro: osinfo["ID"], Release: osinfo["VERSION_ID"], Arch: runtime.GOARCH, ABI: abi}
	if k.Arch != "amd64" {
		return k, fmt.Errorf("unsupported architecture %s", k.Arch)
	}
	var cmd *exec.Cmd
	switch k.Distro {
	case "debian":
		if (k.Release != "12" || osinfo["VERSION_CODENAME"] != "bookworm") && (k.Release != "13" || osinfo["VERSION_CODENAME"] != "trixie") {
			return k, fmt.Errorf("unsupported Debian release")
		}
		cmd = exec.Command("dpkg-query", "-W", "-f=${db:Status-Eflag}.${db:Status-Status} ${Package} ${Architecture} ${Version}", "linux-image-"+abi)
	case "rocky":
		if !model.RockyStable(osinfo["RELEASE_TYPE"], osinfo["VERSION"]) {
			return k, fmt.Errorf("Rocky beta or prerelease is unsupported")
		}
		k.Release, _, _ = strings.Cut(k.Release, ".")
		cmd = exec.Command("rpm", "-q", "kernel-core-"+abi, "--qf", "%{NAME} %{ARCH} %{EPOCHNUM} %{VERSION}-%{RELEASE}\\n")
	default:
		return k, fmt.Errorf("unsupported distribution %q", k.Distro)
	}
	data, err := cmd.Output()
	if err != nil {
		return k, fmt.Errorf("official running kernel package lookup: %w", err)
	}
	f := strings.Fields(string(data))
	if k.Distro == "debian" {
		if len(f) != 4 || f[0] != "ok.installed" || f[1] != "linux-image-"+abi || f[2] != "amd64" {
			return k, fmt.Errorf("expected installed Debian linux-image-%s:amd64", abi)
		}
		if !strings.Contains(" "+readTrim(versionPath)+" ", " Debian "+f[3]+" ") {
			return k, fmt.Errorf("running Debian build differs from installed package %s; boot the matching official kernel", f[3])
		}
	} else if len(f) != 4 || f[0] != "kernel-core" || f[1] != "x86_64" || f[2] != "0" {
		return k, fmt.Errorf("expected Rocky kernel-core.x86_64")
	}
	k.Version = f[3]
	notes, err := os.ReadFile(filepath.Clean(notesPath))
	if err != nil {
		return k, err
	}
	k.BuildID, err = RunningBuildID(notes)
	if err != nil {
		return k, err
	}
	if k.Track() == "" {
		return k, fmt.Errorf("unsupported default AMD64 kernel: %+v", *k)
	}
	return k, nil
}
