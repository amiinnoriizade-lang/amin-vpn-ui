package job

import "testing"

func TestNativeInboundIDIsStableAndPositive(t *testing.T) {
 a:=nativeInboundID("amin-test-vless-10085")
 b:=nativeInboundID("amin-test-vless-10085")
 c:=nativeInboundID("amin-test-vless-10086")
 if a<=0 { t.Fatalf("expected positive id, got %d",a) }
 if a!=b { t.Fatalf("same tag produced different ids: %d != %d",a,b) }
 if a==c { t.Fatalf("different tags collided: %d",a) }
}
