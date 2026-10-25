"""Reproducible same-machine diagnostic, not a production TLS transport."""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from cr01_sc import binary as binary
from tools.native import COMPILER, compile_native, openssl_flags
from cr01_sc.native import native_environment, generate_native_identity, write_native_pin
PROFILES=("cr01","tls-classical","tls-hybrid","tls-pq","aes-reuse","aes-fresh")
SIZES=((64,400),(1024,400),(16384,400),(65536,100),(1048576,30))

def stats(values):
    ordered=sorted(values)
    return {"samples":len(values),"mean_ms":statistics.mean(values),"p50_ms":ordered[(len(values)-1)//2],
            "p95_ms":ordered[math.ceil(len(values)*.95)-1],"raw_ms":values}

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def sources():
    paths=list((ROOT/"src/cpp").glob("*.hpp"))+[ROOT/"src/cpp/main.cpp"]
    paths+=list(Path(__file__).parent.glob("*.py"))+list((ROOT/"tests/benchmarks/cpp").glob("*.hpp"))+list((ROOT/"tests/benchmarks/cpp").glob("*.cpp"))
    paths+=[ROOT/"src/python/cr01_sc/binary.py",ROOT/"src/python/cr01_sc/native.py",ROOT/"tools/native.py"]
    return {p.relative_to(ROOT).as_posix():digest(p) for p in sorted(paths)}

class Peer:
    """Identical process/pipe/queue driver for actual CR01 and diagnostic baselines."""
    def __init__(self,args):
        self.process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                      bufsize=0,env=native_environment())
        self.queue=queue.Queue(maxsize=4)
        self.lock=threading.Lock()
        def reader():
            try:
                while True:
                    head=binary.read_exact(self.process.stdout,16,clean_eof=True)
                    if head is None: break
                    magic,op,status,phase,reserved,n,m=binary.HEADER.unpack(head)
                    if magic!=b"CRB1" or reserved or n>binary.MAX_RECORD or m>4096: raise ValueError("bad response header")
                    if status==1:
                        if head!=binary.REJECTION: raise ValueError("bad rejection")
                        value={"status":"rejected"}
                    elif status==2:
                        if op!=0 or phase not in (1,2) or n>32768: raise ValueError("bad ready")
                        value={"status":"ready","public_bytes":binary.read_exact(self.process.stdout,n),
                               "openssl":binary.read_exact(self.process.stdout,m).decode("ascii")}
                    else:
                        if status!=0 or op not in binary.OPERATIONS.values() or phase not in binary.PHASES or m!=(16 if phase==6 else 0):
                            raise ValueError("bad response status")
                        value={"status":"ok","op":op,"phase":phase,"data":binary.read_exact(self.process.stdout,n),
                               "metadata":binary.read_exact(self.process.stdout,m)}
                    self.queue.put(value,timeout=5)
            except (OSError,ValueError,queue.Full): pass
            finally:
                try: self.queue.put(None,timeout=1)
                except queue.Full: pass
        self.thread=threading.Thread(target=reader,daemon=True);self.thread.start()
        try:
            self.ready=self.read()
            if self.ready["status"]!="ready": raise RuntimeError("app startup rejected")
        except Exception:
            self.close();raise
    def read(self):
        try: result=self.queue.get(timeout=20)
        except queue.Empty:
            self.close();raise RuntimeError("comparison app timeout") from None
        if result is None:
            self.close();raise RuntimeError("comparison app EOF")
        return result
    def command(self,op,data=b""):
        with self.lock:
            binary.write_all(self.process.stdin,binary.request(op,data))
            value=self.read()
        if value.get("status")!="ok": raise ValueError("comparison command rejected")
        if value["op"]!=binary.OPERATIONS[op]: raise ValueError("wrong operation reply")
        return value
    def send(self,data): return self.command("send",data)["data"]
    def receive(self,data): return self.command("receive",data)["data"]
    def close(self):
        if self.process.poll() is None: self.process.terminate()
        self.process.wait(timeout=10)
        for handle in (self.process.stdin,self.process.stdout,self.process.stderr):
            if handle and not handle.closed: handle.close()
        self.thread.join(timeout=2)

def handshake(i,r,profile):
    if profile=="cr01":
        a=i.command("start")["data"];b=r.command("respond",a)["data"]
        c=i.command("finish",b)["data"];d=r.command("accept",c)["data"];i.command("confirm",d)
        return len(a)+len(b)+len(c)+len(d)
    current=i.command("start");wire=len(current["data"]);done_i=current["phase"]==6;done_r=False
    incoming=current["data"]
    for index in range(16):
        peer=r if index%2==0 else i
        response=peer.command("respond" if index%2==0 else "finish",incoming)
        wire+=len(response["data"]);incoming=response["data"]
        if index%2==0: done_r=response["phase"]==6
        else: done_i=response["phase"]==6
        if done_i and done_r:
            if incoming: raise AssertionError("unexpected post-handshake bytes; tickets disabled")
            return wire
    raise RuntimeError("app handshake iteration bound")

def tls_fragments(frame):
    position=count=0
    while position<len(frame):
        if len(frame)-position<5: raise AssertionError("TLS record length")
        n=int.from_bytes(frame[position+3:position+5],"big");position+=5+n;count+=1
    if position!=len(frame): raise AssertionError("TLS record truncation")
    return count

def app_worker(profile,exe,cr01,work,quick):
    def pair():
        own_temp=None
        if profile=="cr01":
            def command(role):
                own,other=("i","r") if role=="initiator" else ("r","i")
                return [str(cr01),"--role",role,"--identity",str(work/(own+".pem")),"--peer-public",str(work/(other+".pub")),
                        "--application",b"matched-tls-comparison".hex(),"--epoch","1","--transport","binary"]
        else:
            creds=work
            if profile.startswith("aes-"):
                own_temp=tempfile.TemporaryDirectory(prefix="aes-fresh-pair-",dir=work)
                creds=Path(own_temp.name);(creds/"aes-keys.bin").write_bytes(os.urandom(64))
            def command(role): return [str(exe),"app",profile,str(creds),role]
        peers=[]
        try:
            peers=[Peer(command("initiator"))];peers.append(Peer(command("responder")))
            return *peers,own_temp
        except Exception:
            for peer in peers: peer.close()
            if own_temp: own_temp.cleanup()
            raise
    def cleanup(i,r,tmp):
        i.close();r.close()
        if tmp: tmp.cleanup()
    samples=[];wire=None
    if not profile.startswith("aes-"):
        for index in range(-1,2 if quick else 5):
            i,r,tmp=pair()
            try:
                start=time.perf_counter_ns();wire=handshake(i,r,profile);duration=(time.perf_counter_ns()-start)/1e6
                if index>=0: samples.append(duration)
            finally: cleanup(i,r,tmp)
    i,r,tmp=pair()
    try:
        if not profile.startswith("aes-"): handshake(i,r,profile)
        if profile.startswith("tls-"):
            details=json.loads(i.command("status")["data"])
            assert details["version"]=="TLSv1.3" and details["cipher"]=="TLS_AES_256_GCM_SHA384" and not details["resumed"]
        else: details=None
        records=[]
        for size,count in SIZES:
            if quick: count=5
            data=b"Z"*size
            for _ in range(5): assert r.receive(i.send(data))==data
            times=[]
            for index in range(count):
                sender,receiver=(i,r) if index%2==0 else (r,i)
                start=time.perf_counter_ns();frame=sender.send(data);plain=receiver.receive(frame)
                times.append((time.perf_counter_ns()-start)/1e6)
                if plain!=data: raise AssertionError("app plaintext mismatch")
            records.append({"payload_bytes":size,"encoded_bytes":len(frame),"fragments":tls_fragments(frame) if profile.startswith("tls-") else 1,**stats(times)})
        return {"panel":"binary-pipes","profile":profile,"openssl":i.ready["openssl"],
                "handshake":{**stats(samples),"wire_bytes":wire} if samples else None,"negotiated":details,"records":records}
    finally: cleanup(i,r,tmp)

def aggregate(rows):
    summary=[]
    for panel in ("in-process","binary-pipes"):
        for profile in PROFILES:
            selected=[x for x in rows if x["profile"]==profile and x["panel"]==panel]
            def means(items):
                values=[x["mean_ms"] for x in items]
                return {"median_mean_ms":statistics.median(values),"min_mean_ms":min(values),"max_mean_ms":max(values)}
            hs=[x["handshake"] for x in selected if x["handshake"] is not None]
            records=[]
            for size,_ in SIZES:
                samples=[next(y for y in x["records"] if y["payload_bytes"]==size) for x in selected]
                records.append({"payload_bytes":size,**means(samples),"encoded_bytes":samples[0]["encoded_bytes"],"fragments":samples[0]["fragments"]})
            summary.append({"panel":panel,"profile":profile,"handshake":{**means(hs),"wire_bytes_range":[min(x["wire_bytes"] for x in hs),max(x["wire_bytes"] for x in hs)]} if hs else None,"records":records})
    primitive=[x for x in rows if x["panel"]=="primitive-only"]
    if primitive:
        records=[]
        for size,_ in SIZES:
            values=[next(x["mean_ms"] for x in row["records"] if x["payload_bytes"]==size) for row in primitive]
            records.append({"payload_bytes":size,"median_mean_ms":statistics.median(values),"min_mean_ms":min(values),"max_mean_ms":max(values)})
        summary.append({"panel":"primitive-only","profile":"aes-primitive","handshake":None,"records":records})
    return summary

def human(report):
    lines=["CR01-SC vs OpenSSL TLS 1.3 / AES-256-GCM", "", "Median of per-run means; one seal + authenticated receive, not network RTT.",
           f"Same compiler/OpenSSL/machine; no external AAD; {report['repeats']} repeated fresh worker processes per profile/panel.",""]
    for panel in ("in-process","binary-pipes","primitive-only"):
        lines += [panel,"profile | handshake ms | 64 B us | 1 KiB us | 16 KiB us | 64 KiB ms | 1 MiB ms"]
        for row in report["summary"]:
            if row["panel"]!=panel: continue
            values=[x["median_mean_ms"] for x in row["records"]]
            lines.append(row["profile"]+" | "+(f"{row['handshake']['median_mean_ms']:.4f}" if row["handshake"] else "N/A (preprovisioned keys)")+
                         " | "+" | ".join(f"{v*1000:.3f}" if index<3 else f"{v:.4f}" for index,v in enumerate(values)))
        lines.append("")
    lines += ["Profiles:","tls-classical: TLS1.3 X25519 + mutual ECDSA-P256 certificates/signatures.",
              "tls-hybrid: TLS1.3 X25519MLKEM768 + mutual ECDSA-P256 certificates/signatures.",
              "tls-pq: TLS1.3 X25519MLKEM768 + mutual ML-DSA-65 certificates/signatures.",
              "All TLS: chain + exact leaf pin + client hostname verification, AES-256-GCM/SHA384, no tickets/resumption/0-RTT.",
              "CR01: pinned ML-DSA-65, ephemeral ML-KEM-768, SHA256/HKDF, AES-256-GCM; custom research protocol.",
              "AES: preprovisioned-key framed baselines, no handshake, peer authentication, replay policy, forward secrecy or restart guarantee.",
              "Both fresh and reused EVP-context framed AES costs are shown. The separate primitive-only row uses preallocated buffers and no framing/IPC.",
              "TLS sends leaf certificates only; the pretrusted root is NOT transmitted. Actual sent and verified chain lengths are asserted.","",report["claim_boundary"],
              "", "Source references: https://www.rfc-editor.org/rfc/rfc8446 ; https://docs.openssl.org/3.6/man3/SSL_CTX_set_verify/ ; https://docs.openssl.org/3.6/man3/SSL_CTX_set1_sigalgs/",""]
    return "\n".join(lines)

def main():
    parser=argparse.ArgumentParser();parser.add_argument("--out",type=Path);parser.add_argument("--repeats",type=int,default=5,choices=range(1,6))
    parser.add_argument("--worker",choices=PROFILES);parser.add_argument("--exe",type=Path);parser.add_argument("--cr01",type=Path);parser.add_argument("--work",type=Path)
    parser.add_argument("--quick",action="store_true")
    parser.add_argument("--cr01-source",type=Path,help="Optional preserved native src directory for before/after diagnostics")
    args=parser.parse_args()
    if args.worker:
        print(json.dumps(app_worker(args.worker,args.exe,args.cr01,args.work,args.quick)));return
    if args.out is None: parser.error("--out required")
    args.out.mkdir(parents=True,exist_ok=False)
    before=sources()
    selected=(args.cr01_source or ROOT/"src/cpp").resolve()
    selected_hashes={p.name:digest(p) for p in selected.glob("*") if p.suffix in (".hpp",".cpp")}
    if "main.cpp" not in selected_hashes: raise ValueError("native source directory is incomplete")
    license_before=digest(ROOT/"LICENSE")
    started=datetime.now(timezone.utc).isoformat();rows=[]
    with tempfile.TemporaryDirectory(prefix="cr01-matched-tls-") as temporary:
        work=Path(temporary);exe=work/"comparison.exe";actual=work/"cr01.exe"
        app_command=[str(COMPILER),"-std=c++20","-O3","-DNDEBUG","-Wall","-Wextra","-Wpedantic","-Werror",
                     str(selected/"main.cpp"),*openssl_flags(),"-o",str(actual)]
        app_compile=subprocess.run(app_command,env=native_environment(),capture_output=True,text=True,timeout=120)
        (args.out/"app-compile.log").write_text(app_compile.stdout+app_compile.stderr,encoding="utf-8")
        if app_compile.returncode: raise RuntimeError(app_compile.stderr)
        command=[str(COMPILER),"-std=c++20","-O3","-DNDEBUG","-Wall","-Wextra","-Wpedantic","-Werror",
                 "-I",str(selected),str((ROOT/"tests/benchmarks/cpp/tls_main.cpp")),
                 *openssl_flags(tls=True),"-o",str(exe)]
        compiled=subprocess.run(command,env=native_environment(),capture_output=True,text=True,timeout=120)
        (args.out/"compile.log").write_text(compiled.stdout+compiled.stderr,encoding="utf-8")
        if compiled.returncode: raise RuntimeError(compiled.stdout+compiled.stderr)
        subprocess.run([str(exe),"provision","all",str(work)],env=native_environment(),check=True,capture_output=True,timeout=30)
        for own in ("i","r"):
            public=generate_native_identity(actual,work/(own+".pem"));write_native_pin(actual,work/(own+".pub"),public)
        hashes={"diagnostic":digest(exe),"actual_cr01":digest(actual)}
        # Smoke tests include all verifier/tag/replay negative controls, before timing.
        for profile in PROFILES:
            probe=subprocess.run([str(exe),"bench",profile,str(work),"quick"],env=native_environment(),capture_output=True,text=True,timeout=60)
            (args.out/("smoke-"+profile+".log")).write_text(probe.stdout+probe.stderr,encoding="utf-8")
            if probe.returncode: raise RuntimeError("profile smoke failed: "+profile+"\n"+probe.stderr)
        for repeat in range(args.repeats):
            rotated=list(PROFILES[repeat:]+PROFILES[:repeat])
            if repeat%2: rotated.reverse()
            for profile in rotated:
                for panel in (("in-process","binary-pipes") if repeat%2==0 else ("binary-pipes","in-process")):
                    print(f"Repeat {repeat+1}/{args.repeats}: {profile} / {panel}",flush=True)
                    if panel=="in-process": cmd=[str(exe),"bench",profile,str(work)]+(["quick"] if args.quick else [])
                    else:
                        cmd=[sys.executable,str(Path(__file__).resolve()),"--worker",profile,"--exe",str(exe),"--cr01",str(actual),"--work",str(work)]+(["--quick"] if args.quick else [])
                    completed=subprocess.run(cmd,env=native_environment(),capture_output=True,text=True,timeout=180)
                    (args.out/f"repeat-{repeat+1}-{profile}-{panel}.json").write_text(completed.stdout,encoding="utf-8")
                    if completed.returncode:
                        (args.out/"worker-error.log").write_text(completed.stderr,encoding="utf-8")
                        raise RuntimeError("comparison worker failed: "+completed.stderr)
                    row=json.loads(completed.stdout);row["repeat"]=repeat+1;rows.append(row)
                    (args.out/"partial.json").write_text(json.dumps(rows)+"\n",encoding="utf-8")
            print(f"Repeat {repeat+1}/{args.repeats}: preallocated AES primitive",flush=True)
            cmd=[str(exe),"primitive","all",str(work)]+(["quick"] if args.quick else [])
            primitive=subprocess.run(cmd,env=native_environment(),capture_output=True,text=True,timeout=120)
            (args.out/f"repeat-{repeat+1}-aes-primitive.json").write_text(primitive.stdout,encoding="utf-8")
            if primitive.returncode: raise RuntimeError(primitive.stderr)
            row=json.loads(primitive.stdout);row["repeat"]=repeat+1;rows.append(row)
        hardware=subprocess.run(["powershell","-NoProfile","-Command","Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed | ConvertTo-Json -Compress"],capture_output=True,text=True,timeout=15)
        compiler=subprocess.run([str(COMPILER),"--version"],env=native_environment(),capture_output=True,text=True,timeout=10).stdout.splitlines()[0]
        report={"schema":"CR01-MATCHED-TLS-AES-COMPARISON-v1","status":"pass","started_at":started,"finished_at":datetime.now(timezone.utc).isoformat(),
                "repeats":args.repeats,"quick":args.quick,"environment":{"cpu":json.loads(hardware.stdout),"compiler":compiler,"openssl":rows[0]["openssl"]},
                "source_sha256":before,"executables_sha256":hashes,"source_drift":[p for p,h in sources().items() if before.get(p)!=h],
                "license_unchanged":digest(ROOT/"LICENSE")==license_before,"license_sha256":license_before,
                "cr01_source_sha256":selected_hashes,
                "cr01_source_drift":[p.name for p in selected.glob("*") if p.name in selected_hashes and digest(p)!=selected_hashes[p.name]],
                "summary":aggregate(rows),"runs":rows,
                "record_output_policy":"CR01 reuses send_into and consumes receive_owned ciphertext storage, then recycles cleansed storage. TLS/AES return receive buffers. First allocation/growth, plaintext checking and destruction/cleansing remain inside record timing. Binary app wipes raw plaintext storage before final response bytes; JSON before emitting authenticated hex. Available-API comparison, not storage-normalized primitive speed or security equivalence.",
                "claim_boundary":"Local Windows single-thread synthetic engineering comparison, not a network benchmark, server-capacity, constant-time, independent audit, cryptographic equivalence or production/quantum-security proof. No CPU isolation, fixed-clock or thermal/idle gate. TLS uses in-memory BIOs plus equivalent binary pipes in app panel, not TCP. Handshakes exclude credential provisioning, context configuration/disk and process startup; include endpoint creation in core panel. App process creation necessarily precedes timed handshake. TLS authenticates X509 chain/leaf/hostname, unlike bare AES or CR01 pin-only trust. TLS is an ordered stream with 16 KiB records; CR01 permits larger independent records and a replay window. Diagnostic TLS/AES apps are test scaffolds, not production transports. Source bundle/licence untouched."}
        if report["source_drift"] or report["cr01_source_drift"] or not report["license_unchanged"]: raise AssertionError("comparison inputs drifted")
        (args.out/"comparison.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
        compact = {key: value for key, value in report.items() if key != "runs"}
        compact["schema"] = "CR01-MATCHED-TLS-AES-COMPACT-v1"
        compact["run_summaries"] = [
            {key: ([{field: value for field, value in record.items() if field != "raw_ms"} for record in value]
                   if key == "records" else {field: item for field, item in value.items() if field != "raw_ms"}
                   if key == "handshake" and isinstance(value, dict) else value)
             for key, value in row.items() if key != "raw_ms"}
            for row in rows]
        (args.out/"tls_aes.json").write_text(json.dumps(compact,indent=2)+"\n",encoding="utf-8")
        (args.out/"SUMMARY.txt").write_text(human(report),encoding="utf-8")
        print(human(report),flush=True)

if __name__=="__main__": main()

