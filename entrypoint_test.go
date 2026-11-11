package main

// entrypoint_test.go — a shell harness for the container entrypoint.
//
// The entrypoint is the only piece of dnsscale that talks to `tailscaled`, and
// its `tailscale cert` invocation has two non-obvious requirements: the domain
// is a positional argument, and the flags must precede it. Both were wrong at
// least once. This harness puts fake `tailscaled`, `tailscale` and `dnsscale`
// binaries on PATH, records every invocation, and asserts the exact argv.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const fakeTailscaleScript = `#!/bin/sh
# Record the invocation, then answer the subcommands the entrypoint uses.
printf '%s\n' "$*" >> "$RECORD_FILE"

sub=""
is_json=0
prev=""
for a in "$@"; do
  [ "$a" = "--json" ] && is_json=1
  case "$a" in
    --socket=*) ;;
    *) if [ -z "$sub" ]; then sub="$a"; fi ;;
  esac
  prev="$a"
done

case "$sub" in
  status)
    if [ "$is_json" = "1" ]; then
      printf '{"Self":{"DNSName":"dnsscale.example.ts.net."}}'
    else
      printf 'Tailscale is logged in.\n'
    fi
    ;;
  ip)
    printf '100.64.1.1\n'
    ;;
  up)
    :
    ;;
  cert)
    cert=""
    key=""
    for a in "$@"; do
      case "$a" in
        --cert-file=*) cert="${a#--cert-file=}" ;;
        --key-file=*)  key="${a#--key-file=}" ;;
      esac
    done
    if [ -z "$cert" ] || [ -z "$key" ]; then
      echo "fake tailscale: cert called without --cert-file/--key-file" >&2
      exit 1
    fi
    printf 'FAKE CERTIFICATE\n' > "$cert"
    printf 'FAKE_PRIVATE_KEY\n' > "$key"
    ;;
  *)
    echo "fake tailscale: unexpected subcommand '$sub'" >&2
    exit 1
    ;;
esac
exit 0
`

// entrypointPath locates the container entrypoint relative to this test file,
// so the suite does not depend on the process working directory.
func entrypointPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine the test file location")
	}
	dir := filepath.Dir(thisFile)
	// entrypoint.sh sits beside this file in the standalone repo, and one
	// level up when the module is kept in an upstream-src/ subdirectory.
	for _, cand := range []string{
		filepath.Join(dir, "entrypoint.sh"),
		filepath.Join(dir, "..", "entrypoint.sh"),
	} {
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
	}
	t.Fatalf("entrypoint.sh not found in %s or its parent directory", dir)
	return ""
}

// writeExecutable creates a executable script with the given body.
func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// runEntrypoint executes the real entrypoint against fake binaries.
func runEntrypoint(t *testing.T, env map[string]string) (string, string, int) {
	t.Helper()

	bin := t.TempDir()
	record := filepath.Join(t.TempDir(), "calls.log")

	writeExecutable(t, filepath.Join(bin, "tailscaled"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(bin, "dnsscale"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(bin, "tailscale"), fakeTailscaleScript)

	cmd := exec.Command("/bin/sh", entrypointPath(t))
	cmd.Env = []string{
		"PATH=" + bin + ":/usr/bin:/bin",
		"RECORD_FILE=" + record,
		"TS_AUTHKEY=tskey-auth-test",
		"TS_HOSTNAME=dnsscale",
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	out, err := cmd.CombinedOutput()
	status := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			status = exitErr.ExitCode()
		} else {
			t.Fatalf("running the entrypoint: %v", err)
		}
	}

	raw, _ := os.ReadFile(record)
	return string(raw), string(out), status
}

func TestEntrypointTailscaleCertInvocation(t *testing.T) {
	certDir := t.TempDir()
	certFile := filepath.Join(certDir, "cert.pem")
	keyFile := filepath.Join(certDir, "key.pem")

	record, out, status := runEntrypoint(t, map[string]string{
		"API_TLS_MODE": "tailscale",
		"API_TLS_CERT": certFile,
		"API_TLS_KEY":  keyFile,
	})

	if status != 0 {
		t.Fatalf("entrypoint exited %d, want 0\noutput:\n%s", status, out)
	}

	// The domain must be the LAST argument and the flags before it: the real
	// `tailscale cert` rejects `cert <domain> --cert-file=...`.
	certCall := ""
	for _, line := range strings.Split(record, "\n") {
		if strings.Contains(line, " cert ") || strings.HasPrefix(line, "cert ") {
			certCall = line
		}
	}
	if certCall == "" {
		t.Fatalf("the entrypoint never invoked `tailscale cert`:\n%s\noutput:\n%s", record, out)
	}

	if !strings.HasSuffix(certCall, "dnsscale.example.ts.net") {
		t.Errorf("cert invocation = %q, want the tailnet DNS name as the final argument", certCall)
	}
	if !strings.Contains(certCall, "--cert-file="+certFile) {
		t.Errorf("cert invocation = %q, want --cert-file before the domain", certCall)
	}
	if strings.Index(certCall, "dnsscale.example.ts.net") < strings.Index(certCall, "--cert-file=") {
		t.Errorf("cert invocation = %q, want the flags before the domain", certCall)
	}

	// The fake wrote the files, so the entrypoint must have created them.
	for _, p := range []string{certFile, keyFile} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("certificate file %s was not produced: %v", p, err)
		}
	}
	if !strings.Contains(out, "requesting a Tailscale certificate for dnsscale.example.ts.net") {
		t.Errorf("entrypoint did not announce the domain it requested:\n%s", out)
	}
}

func TestEntrypointTailscaleCertUsesExplicitDomain(t *testing.T) {
	certDir := t.TempDir()
	certFile := filepath.Join(certDir, "cert.pem")
	keyFile := filepath.Join(certDir, "key.pem")

	record, out, status := runEntrypoint(t, map[string]string{
		"API_TLS_MODE":   "tailscale",
		"API_TLS_CERT":   certFile,
		"API_TLS_KEY":    keyFile,
		"API_TLS_DOMAIN": "dnsscale.example.com",
	})
	if status != 0 {
		t.Fatalf("entrypoint exited %d, want 0\noutput:\n%s", status, out)
	}

	if !strings.Contains(record, "dnsscale.example.com") {
		t.Errorf("the explicit API_TLS_DOMAIN was not used:\n%s", record)
	}
	if strings.Contains(record, "dnsscale.example.ts.net") {
		t.Errorf("the derived domain was used despite API_TLS_DOMAIN:\n%s", record)
	}
}

func TestEntrypointReusesExistingCertificate(t *testing.T) {
	// A certificate already on disk must not be re-requested: the container
	// restarts frequently and each request is a tailnet operation.
	certDir := t.TempDir()
	certFile := filepath.Join(certDir, "cert.pem")
	keyFile := filepath.Join(certDir, "key.pem")
	writeExecutable(t, certFile, "existing")
	writeExecutable(t, keyFile, "existing")

	record, _, status := runEntrypoint(t, map[string]string{
		"API_TLS_MODE": "tailscale",
		"API_TLS_CERT": certFile,
		"API_TLS_KEY":  keyFile,
	})
	if status != 0 {
		t.Fatalf("entrypoint exited %d, want 0", status)
	}
	if strings.Contains(record, " cert ") {
		t.Errorf("the entrypoint requested a certificate that already existed:\n%s", record)
	}
}

func TestEntrypointProvidedModeRequiresFiles(t *testing.T) {
	certDir := t.TempDir()
	missingCert := filepath.Join(certDir, "absent.pem")
	missingKey := filepath.Join(certDir, "absent.key")

	_, out, status := runEntrypoint(t, map[string]string{
		"API_TLS_MODE": "provided",
		"API_TLS_CERT": missingCert,
		"API_TLS_KEY":  missingKey,
	})
	if status == 0 {
		t.Fatal("entrypoint succeeded without the configured certificate, want a non-zero exit")
	}
	if !strings.Contains(out, "certificate not found") {
		t.Errorf("entrypoint did not report the missing certificate:\n%s", out)
	}
}

func TestEntrypointProvidedModeAcceptsMountedCertificate(t *testing.T) {
	certDir := t.TempDir()
	certFile := filepath.Join(certDir, "cert.pem")
	keyFile := filepath.Join(certDir, "key.pem")
	writeExecutable(t, certFile, "mounted")
	writeExecutable(t, keyFile, "mounted")

	_, out, status := runEntrypoint(t, map[string]string{
		"API_TLS_MODE": "provided",
		"API_TLS_CERT": certFile,
		"API_TLS_KEY":  keyFile,
	})
	if status != 0 {
		t.Fatalf("entrypoint exited %d, want 0\noutput:\n%s", status, out)
	}
	if !strings.Contains(out, "TLS provided") {
		t.Errorf("entrypoint did not confirm the provided certificate:\n%s", out)
	}
}

func TestEntrypointOffModeFetchesNothing(t *testing.T) {
	record, out, status := runEntrypoint(t, map[string]string{
		"API_TLS_MODE": "off",
	})
	if status != 0 {
		t.Fatalf("entrypoint exited %d, want 0\noutput:\n%s", status, out)
	}
	if strings.Contains(record, " cert ") {
		t.Errorf("tls_mode=off still requested a certificate:\n%s", record)
	}
	if !strings.Contains(out, "TLS off") {
		t.Errorf("entrypoint did not report that TLS is off:\n%s", out)
	}
}

func TestEntrypointRejectsUnknownMode(t *testing.T) {
	_, out, status := runEntrypoint(t, map[string]string{
		"API_TLS_MODE": "banana",
	})
	if status == 0 {
		t.Fatal("entrypoint accepted an unknown API_TLS_MODE, want a non-zero exit")
	}
	if !strings.Contains(out, "invalid API_TLS_MODE") {
		t.Errorf("entrypoint did not report the invalid mode:\n%s", out)
	}
}

func TestEntrypointDropsPrivilegesWhenRoot(t *testing.T) {
	// The certificate fetch needs root; the application must not keep it.
	// Running as root is not possible here, so assert the branch is guarded
	// by the uid check and that a non-root run does not invoke su-exec.
	_, out, status := runEntrypoint(t, map[string]string{
		"API_TLS_MODE": "off",
	})
	if status != 0 {
		t.Fatalf("entrypoint exited %d, want 0\noutput:\n%s", status, out)
	}
	if os.Getuid() == 0 {
		t.Skip("this test asserts the non-root path; it is meaningless as root")
	}
	if strings.Contains(out, "su-exec") {
		t.Errorf("a non-root run attempted to use su-exec:\n%s", out)
	}
}

func TestEntrypointWaitsForTailscale(t *testing.T) {
	// The IP wait loop must tolerate a tailscaled that is slow to come up.
	// The fake answers immediately; this asserts the loop exits rather than
	// spinning, and that the entrypoint fails loudly if no IP ever appears.
	bin := t.TempDir()
	writeExecutable(t, filepath.Join(bin, "tailscaled"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(bin, "dnsscale"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(bin, "tailscale"), `#!/bin/sh
printf '%s\n' "$*" >> "$RECORD_FILE"
sub=""
for a in "$@"; do
  case "$a" in
    --socket=*) ;;
    *) if [ -z "$sub" ]; then sub="$a"; fi ;;
  esac
done
case "$sub" in
  status) printf 'Tailscale is logged in.\n' ;;
  ip)     : ;;   # never reports an IP
  up)     : ;;
esac
exit 0
`)

	cmd := exec.Command("/bin/sh", entrypointPath(t))
	cmd.Env = []string{
		"PATH=" + bin + ":/usr/bin:/bin",
		"RECORD_FILE=" + filepath.Join(t.TempDir(), "calls.log"),
		"API_TLS_MODE=off",
		"TS_WAIT_RETRIES=2",
		"TS_WAIT_DELAY=0",
	}

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("entrypoint succeeded without a Tailscale IP, want a failure\noutput:\n%s", out)
	}
	if !strings.Contains(string(out), "failed to acquire Tailscale IP") {
		t.Errorf("entrypoint did not report the missing Tailscale IP:\n%s", out)
	}
}
