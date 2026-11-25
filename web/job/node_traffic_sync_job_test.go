package job

import (
 "testing"
 "time"
)

func TestNodeSpeedDeltaUsesRealElapsedWindow(t *testing.T) {
 prev:=map[string]nodeCounterSample{"alice":{up:1000,down:2000,at:1000}}
 cur:=map[string]*nodeClientAggregate{"alice":{Up:3000,Down:6000}}
 next,deltas:=nodeSpeedDelta(prev,cur,15000)
 if len(deltas)!=1 { t.Fatalf("expected one delta, got %#v",deltas) }
 if deltas[0].Up!=1000 || deltas[0].Down!=2000 {
  t.Fatalf("normalized delta = up %d down %d, want 1000/2000",deltas[0].Up,deltas[0].Down)
 }
 if next["alice"].at!=15000 { t.Fatalf("baseline timestamp = %d",next["alice"].at) }
}

func TestNodeSpeedDeltaRebaselinesAfterCounterReset(t *testing.T) {
 prev:=map[string]nodeCounterSample{"alice":{up:9000,down:8000,at:time.Now().UnixMilli()}}
 cur:=map[string]*nodeClientAggregate{"alice":{Up:100,Down:200}}
 next,deltas:=nodeSpeedDelta(prev,cur,time.Now().UnixMilli())
 if len(deltas)!=0 { t.Fatalf("counter reset must not create a speed spike: %#v",deltas) }
 if next["alice"].up!=100 || next["alice"].down!=200 { t.Fatalf("counter was not rebaselined: %#v",next["alice"]) }
}
