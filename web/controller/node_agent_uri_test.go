package controller

import (
 "encoding/json"
 "strings"
 "testing"

 "github.com/mhsanaei/3x-ui/v2/web/job"
)

func TestBuildNativeAgentShareLinkVLESSReality(t *testing.T) {
 settings:=map[string]any{"network":"tcp","security":"reality","realitySettings":map[string]any{
  "serverName":"example.com","fingerprint":"chrome","settings":map[string]any{"publicKey":"public-key","shortId":"abcd","spiderX":"/"},
 }}
 raw,err:=json.Marshal(settings); if err!=nil { t.Fatal(err) }
 ib:=job.NativeAgentInbound{Tag:"amin-vless-443",Port:443,Protocol:"vless",StreamSettings:raw}
 link,protocol,_,err:=buildNativeAgentShareLink("203.0.113.10","test",ib,map[string]any{"email":"alice","id":"11111111-1111-4111-8111-111111111111","flow":"xtls-rprx-vision"},"alice")
 if err!=nil { t.Fatal(err) }
 for _,part:=range []string{"vless://","@203.0.113.10:443","security=reality","pbk=public-key","sid=abcd","flow=xtls-rprx-vision"} {
  if !strings.Contains(link,part) { t.Fatalf("link missing %q: %s",part,link) }
 }
 if protocol!="vless" { t.Fatalf("protocol=%s",protocol) }
}

func TestBuildNativeAgentShareLinkRejectsRealityWithoutPublicKey(t *testing.T) {
 raw:=json.RawMessage(`{"network":"tcp","security":"reality","realitySettings":{"settings":{"shortId":"abcd"}}}`)
 ib:=job.NativeAgentInbound{Tag:"reality",Port:443,Protocol:"vless",StreamSettings:raw}
 if _,_,_,err:=buildNativeAgentShareLink("203.0.113.10","test",ib,map[string]any{"email":"alice","id":"uuid"},"alice"); err==nil {
  t.Fatal("expected missing Reality public key error")
 }
}

func TestBuildNativeAgentShareLinkVMessWS(t *testing.T) {
 raw:=json.RawMessage(`{"network":"ws","security":"tls","tlsSettings":{"serverName":"example.com"},"wsSettings":{"path":"/ws","headers":{"Host":"cdn.example.com"}}}`)
 ib:=job.NativeAgentInbound{Tag:"vmess-ws",Port:8443,Protocol:"vmess",StreamSettings:raw}
 link,protocol,_,err:=buildNativeAgentShareLink("vpn.example.com","test",ib,map[string]any{"email":"alice","id":"11111111-1111-4111-8111-111111111111","alterId":0},"alice")
 if err!=nil { t.Fatal(err) }
 if !strings.HasPrefix(link,"vmess://") || protocol!="vmess" { t.Fatalf("unexpected result: %s (%s)",link,protocol) }
}

func TestValidNodeHost(t *testing.T) {
 for _,host:=range []string{"203.0.113.10","vpn.example.com","2001:db8::1"} {
  if !validNodeHost(host) { t.Errorf("expected valid host %q",host) }
 }
 for _,host:=range []string{"","https://example.com","example.com/path","user@example.com"} {
  if validNodeHost(host) { t.Errorf("expected invalid host %q",host) }
 }
}
