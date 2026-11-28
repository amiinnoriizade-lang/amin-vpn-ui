package job

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/nodetoken"
)

func SSHNodeConfigFromModel(n model.Node) (SSHNodeConfig,error) {
	key,err:=nodetoken.Decrypt(n.SSHPrivateKey)
	if err!=nil { return SSHNodeConfig{},fmt.Errorf("decrypt SSH private key: %w",err) }
	port:=n.SSHPort
	if port==0 { port=22 }
	return SSHNodeConfig{Address:n.Address,Port:port,Username:n.SSHUsername,PrivateKey:[]byte(key),Timeout:15*time.Second},nil
}

// SSHNodePersistVLESSClient updates config.json atomically and validates the
// candidate with xray -test before replacing the active file. The remote Python
// program is constant; all user data is delivered as JSON on stdin.
func SSHNodePersistVLESSClient(ctx context.Context,n model.Node,tag,email,id,flow string,add bool) error {
	if !n.SSHMode { return fmt.Errorf("node is not configured for direct SSH") }
	tag,email,id=strings.TrimSpace(tag),strings.TrimSpace(email),strings.TrimSpace(id)
	if tag=="" || email=="" || (add && id=="") { return fmt.Errorf("inbound tag and email are required; UUID is required when adding") }
	payload,err:=json.Marshal(map[string]any{"tag":tag,"email":email,"id":id,"flow":flow,"add":add})
	if err!=nil { return err }
	cfg,err:=SSHNodeConfigFromModel(n)
	if err!=nil { return err }
	const script = `import json, os, sys, tempfile, shutil, subprocess, time
p="/usr/local/etc/xray/config.json"
xray="/usr/local/bin/xray"
try:
    req=json.load(sys.stdin)
    with open(p, "r", encoding="utf-8") as f: config=json.load(f)
    matches=[i for i in config.get("inbounds",[]) if i.get("tag")==req["tag"]]
    if len(matches)!=1: raise RuntimeError("inbound tag was not found uniquely")
    inbound=matches[0]
    if str(inbound.get("protocol","")).lower()!="vless": raise RuntimeError("only VLESS inbounds are currently supported for persistent SSH management")
    settings=inbound.get("settings") or {}
    clients=settings.setdefault("clients",[])
    email=req["email"]
    if req["add"]:
        if any(str(c.get("email","")).lower()==email.lower() for c in clients): raise RuntimeError("client email already exists in inbound")
        item={"id":req["id"],"email":email}
        if req.get("flow"): item["flow"]=req["flow"]
        clients.append(item)
    else:
        before=len(clients)
        settings["clients"]=[c for c in clients if str(c.get("email","")).lower()!=email.lower()]
        if len(settings["clients"])==before: raise RuntimeError("client email not found in inbound")
    directory=os.path.dirname(p)
    fd,tmp=tempfile.mkstemp(prefix=".amin-xray-",suffix=".json",dir=directory)
    os.close(fd)
    try:
        with open(tmp,"w",encoding="utf-8") as f:
            json.dump(config,f,ensure_ascii=False,indent=2)
            f.write("\n")
        shutil.copystat(p,tmp)
        check=subprocess.run([xray,"run","-test","-config",tmp],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=20)
        if check.returncode!=0: raise RuntimeError("Xray config validation failed: "+check.stdout[-1500:])
        backup=p+".bak-aminui-"+time.strftime("%Y%m%d-%H%M%S")
        shutil.copy2(p,backup)
        os.replace(tmp,p)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    print("OK")
except Exception as e:
    print(str(e),file=sys.stderr)
    sys.exit(1)
`
	command:="python3 -c '"+strings.ReplaceAll(script,"'","'\\''")+"'"
	_,err=RunSSHNodeCommandInput(cfg,command,payload)
	if err!=nil { return fmt.Errorf("persist VLESS client in Xray config: %w",err) }
	return nil
}
