package controller

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"strings"
	"testing"
)

func TestNativeShareQRCodeProducesPNGDataURI(t *testing.T) {
	link := "vless://00000000-0000-4000-8000-000000000001@example.com:443?encryption=none#amin-test"
	got, err := nativeShareQRCode(link)
	if err != nil {
		t.Fatalf("nativeShareQRCode() error = %v", err)
	}

	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("QR result must be a PNG data URI, got prefix %q", got[:min(len(got), 32)])
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, prefix))
	if err != nil {
		t.Fatalf("decode QR base64: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode generated QR PNG: %v", err)
	}
	if img.Bounds().Dx() != 256 || img.Bounds().Dy() != 256 {
		t.Fatalf("QR dimensions = %dx%d, want 256x256", img.Bounds().Dx(), img.Bounds().Dy())
	}
}
