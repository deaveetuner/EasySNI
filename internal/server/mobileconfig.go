package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
)

// uuid4 returns a random RFC-4122 UUID string (for the .mobileconfig payloads).
func uuid4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// caDER returns the DER bytes of the MITM CA certificate (decoded from its PEM).
func (s *Server) caDER() []byte {
	blk, _ := pem.Decode(s.mitmdf.CAPEM())
	if blk == nil {
		return nil
	}
	return blk.Bytes
}

// handleMitmdfMobileconfig serves an Apple configuration profile that installs
// the CA on iOS/iPadOS/macOS. Modern iOS no longer installs a bare .crt opened
// in Safari cleanly; a .mobileconfig is recognized as a proper profile under
// Settings → General → VPN & Device Management. (The user must still enable
// trust in Certificate Trust Settings — Apple requires that manual step.)
func (s *Server) handleMitmdfMobileconfig(w http.ResponseWriter, r *http.Request) {
	der := s.caDER()
	if len(der) == 0 {
		http.Error(w, "CA not generated yet — start the Domain-Fronting proxy once", http.StatusNotFound)
		return
	}
	certB64 := base64.StdEncoding.EncodeToString(der)
	profile := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadType</key>
      <string>com.apple.security.root</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>PayloadIdentifier</key>
      <string>com.v2rayez.ca.` + uuid4() + `</string>
      <key>PayloadUUID</key>
      <string>` + uuid4() + `</string>
      <key>PayloadDisplayName</key>
      <string>V2RayEz Domain-Fronting CA</string>
      <key>PayloadCertificateFileName</key>
      <string>V2RayEz-CA.cer</string>
      <key>PayloadContent</key>
      <data>` + certB64 + `</data>
    </dict>
  </array>
  <key>PayloadDisplayName</key>
  <string>V2RayEz CA Certificate</string>
  <key>PayloadDescription</key>
  <string>Installs the V2RayEz domain-fronting root certificate. After installing, enable it in Settings → General → About → Certificate Trust Settings.</string>
  <key>PayloadIdentifier</key>
  <string>com.v2rayez.profile.` + uuid4() + `</string>
  <key>PayloadOrganization</key>
  <string>V2RayEz · MacanDev</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>` + uuid4() + `</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
`
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", "attachment; filename=V2RayEz-CA.mobileconfig")
	_, _ = w.Write([]byte(profile))
}
