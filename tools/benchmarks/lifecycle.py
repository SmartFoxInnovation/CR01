"""Cold process readiness, first-use warm-up, warm handshakes and live records.

Instrumentation is applied to generated source copies only. Uninstrumented
controls supply headline timings; diagnostic self times are not added to them.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cr01_sc.native import NativePeer, complete, generate_native_identity, native_environment, write_native_pin
from tools.native import COMPILER, openssl_flags
from tools.benchmarks.tls import stats

# Exact function markers deliberately fail closed when a source signature changes.
FUNCTIONS = {
    'channel_v2_secret.hpp': [('    explicit Secret(std::size_t size)', 'memory.allocate_lock'),
                             ('    void release()', 'memory.cleanse_release')],
    'channel_v2_crypto.hpp': [('inline Key load_identity(', 'identity.load'),
        ('inline Key generate(', 'key.generate'), ('inline Key public_key(', 'key.import'),
        ('inline Bytes sign(', 'signature.sign'), ('inline void verify(', 'signature.verify'),
        ('inline std::pair<Secret, Bytes> encapsulate(', 'kem.encapsulate'),
        ('inline Secret decapsulate(', 'kem.decapsulate'),
        ('inline Bytes hash_flights(', 'transcript.hash'), ('inline Bytes random_bytes(', 'rng')],
    'channel_v2_endpoint.hpp': [('    Endpoint(const std::string& role', 'endpoint.create'),
        ('    Bytes sign_flight(', 'flight.encode_sign'), ('    FlightPayload verify_flight(', 'flight.parse_verify'),
        ('    void establish(', 'session.establish'), ('    Bytes start(', 'flight.start'),
        ('    Bytes respond(', 'flight.respond'), ('    Bytes finish(', 'flight.finish'),
        ('    Bytes accept(', 'flight.accept'), ('    Bytes confirm(', 'flight.confirm')],
}


def instrument_function(content, marker, label):
    if content.count(marker) != 1:
        raise ValueError('instrumentation marker must occur exactly once: ' + marker)
    begin = content.index('(', content.index(marker)); depth = 1; end = begin + 1
    while depth:
        depth += (content[end] == '(') - (content[end] == ')'); end += 1
    # Endpoint has an initializer list with braces in none of its expressions.
    body = content.index('{', end) + 1
    return content[:body] + ' lifecycle_profile::Scope profile_scope("' + label + '"); ' + content[body:]


def inputs(root=ROOT):
    paths = list((root/'src/cpp').glob('*.hpp')) + [root/'src/cpp/main.cpp']
    paths += [root/p for p in ('tools/benchmarks/lifecycle.py', 'tools/benchmarks/tls.py', 'tools/native.py',
        'tests/benchmarks/cpp/lifecycle.cpp', 'tests/benchmarks/cpp/lifecycle_profile.hpp',
        'src/python/cr01_sc/native.py', 'src/python/cr01_sc/binary.py')]
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def build(root, directory, diagnostic):
    source = directory/'src'; shutil.copytree(root/'src/cpp', source)
    if diagnostic:
        for name, functions in FUNCTIONS.items():
            path = source/name; content = path.read_text(encoding='utf-8')
            for marker, label in functions: content = instrument_function(content, marker, label)
            if name == 'channel_v2_crypto.hpp':
                marker = 'inline void secret_hmac_into(' if 'inline void secret_hmac_into(' in content else 'inline Secret secret_hmac('
                content = instrument_function(content, marker, 'kdf.hmac')
                for label, expression in (
                    ('provider.sign_init', 'EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key)'),
                    ('provider.sign', 'backend_sign(ctx.get(), signature.data(), &size, message.data(), message.size())'),
                    ('provider.verify_init', 'EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key)'),
                    ('provider.verify', 'EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), message.data(), message.size())')):
                    if content.count(expression) != 1: raise ValueError('provider instrumentation marker changed')
                    content = content.replace(expression, 'lifecycle_profile::call("'+label+'",[&]{return '+expression+';})')
            path.write_text('#include "lifecycle_profile.hpp"\n'+content, encoding='utf-8')
    exe = directory/('profile.exe' if diagnostic else 'timing.exe')
    command = [str(COMPILER), '-std=c++20', '-O3', '-DNDEBUG', '-Wall', '-Wextra', '-Wpedantic', '-Werror',
        '-I', str(source), '-I', str(ROOT/'tests/benchmarks/cpp'), str(ROOT/'tests/benchmarks/cpp/lifecycle.cpp'),
        *openssl_flags(), '-o', str(exe)]
    done = subprocess.run(command, env=native_environment(), capture_output=True, text=True, timeout=120)
    (directory/'compile.log').write_text(done.stdout+done.stderr, encoding='utf-8')
    done.check_returncode()
    return exe


def pipe_sample(exe, work):
    peers = []
    start = time.perf_counter_ns()
    try:
        for role, own, other in (('initiator','i','r'), ('responder','r','i')):
            peers.append(NativePeer(exe, role, work/(own+'.pem'), work/(other+'.pub'), application=b'lifecycle-benchmark'))
        ready = (time.perf_counter_ns()-start)/1e6
        start = time.perf_counter_ns(); complete(*peers); handshake = (time.perf_counter_ns()-start)/1e6
        if peers[0].session_id != peers[1].session_id: raise AssertionError('pipe session mismatch')
        return {'cold_start_pair_ready_ms': ready, 'ready_pair_first_handshake_ms': handshake}
    finally:
        for peer in peers: peer.close()


def summarize(runs):
    output = {}
    for stage in ('identity_load','warm_up','fresh_handshake','running_1k','running_1m'):
        means = [statistics.mean(run['timing'][stage]['raw_ms']) for run in runs]
        output[stage] = {'median_mean_ms': statistics.median(means), 'run_means_ms': means}
    for stage in ('cold_start_pair_ready_ms','ready_pair_first_handshake_ms'):
        values = [run['pipes'][stage] for run in runs]
        output[stage] = {'median_ms': statistics.median(values), 'raw_ms': values}
    return output


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--repeats',type=int,default=5)
    parser.add_argument('--baseline',type=Path,help='Optional extracted prior source root; never modified')
    parser.add_argument('--quick',action='store_true',help='Smoke check only; not canonical performance evidence')
    args=parser.parse_args()
    if not 1 <= args.repeats <= 10: parser.error('repeats must be 1..10')
    args.out.mkdir(parents=True,exist_ok=False)
    before=inputs(); roots={'candidate':ROOT}
    if args.baseline: roots['baseline']=args.baseline.resolve()
    executables={}; source_sets={}
    for name, root in roots.items():
        source_sets[name]={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (root/'src/cpp').glob('*') if p.is_file()}
        executables[name]={}
        for mode in ('timing','profile'):
            directory=args.out/name/mode;directory.mkdir(parents=True)
            executables[name][mode]=build(root,directory,mode=='profile')
        # Compile actual uninstrumented app from the same selected source root.
        app=args.out/name/'engine.exe'
        command=[str(COMPILER),'-std=c++20','-O3','-DNDEBUG',str(root/'src/cpp/main.cpp'),*openssl_flags(),'-o',str(app)]
        done=subprocess.run(command,env=native_environment(),capture_output=True,text=True,timeout=120)
        (args.out/name/'app-compile.log').write_text(done.stdout+done.stderr,encoding='utf-8');done.check_returncode()
        executables[name]['app']=app
    runs={name:[] for name in roots}
    with tempfile.TemporaryDirectory(prefix='cr01-lifecycle-') as temp:
        work=Path(temp)
        for name in ('i','r'):
            public=generate_native_identity(executables['candidate']['app'],work/(name+'.pem'))
            write_native_pin(executables['candidate']['app'],work/(name+'.pub'),public)
        for repeat in range(args.repeats):
            order=list(roots) if repeat%2==0 else list(reversed(roots))
            for name in order:
                result={'repeat':repeat,'order':order}
                # Plain control first, so profiler/backend work cannot warm its process.
                for mode in ('timing','profile'):
                    command=[str(executables[name][mode]),str(work/'i.pem'),str(work/'r.pem'),'2' if args.quick else '200']
                    done=subprocess.run(command,env=native_environment(),capture_output=True,text=True,timeout=60)
                    (args.out/name/f'{repeat}-{mode}.json').write_text(done.stdout,encoding='utf-8')
                    (args.out/name/f'{repeat}-{mode}.log').write_text(done.stderr,encoding='utf-8');done.check_returncode()
                    result[mode]=json.loads(done.stdout)
                    expected=6 if args.quick else 204
                    if result[mode]['unique_sessions']!=expected: raise AssertionError('missing fresh sessions')
                    if not all(value['profile']['accounting_valid'] for value in result[mode].values() if isinstance(value,dict)):
                        raise AssertionError('invalid diagnostic accounting')
                result['pipes']=pipe_sample(executables[name]['app'],work);runs[name].append(result)
                print(f'{name} repeat {repeat+1}: pass',flush=True)
    drift=[name for name,value in inputs().items() if before.get(name)!=value]
    report={'schema':'CR01-LIFECYCLE-v1','status':'pass' if not drift else 'fail',
        'generated_at':datetime.now(timezone.utc).isoformat(),'source_sha256':before,'source_drift':drift,
        'platform':platform.platform(),'repeats':args.repeats,'quick':args.quick,
        'source_sets':source_sets,'summary':{name:summarize(value) for name,value in runs.items()},'runs':runs,
        'executable_sha256':{name:{mode:hashlib.sha256(exe.read_bytes()).hexdigest() for mode,exe in modes.items()} for name,modes in executables.items()},
        'boundaries':[
            'Cold start: sequential launch of two real CLI processes through wrapper until both ready. No handshake, provisioning or teardown.',
            'Warm-up: first disposable full in-process handshake including endpoint creation after private identity load. Two further conditioning handshakes disclosed, not headline samples.',
            'Fresh handshake: full v2, new endpoints/KEM/nonces, preloaded identities, three prior full handshakes. No endpoint reset or session resumption.',
            'Running: established bidirectional 1 KiB/1 MiB seal + authenticated receive + payload check and cleanup, five record warm-ups per size.',
            'Pipes handshake: first full handshake in a new ready process pair, not a persistent warmed worker.',
            'Plain control timings supply figures. Instrumented exclusive/inclusive times are diagnostic and perturb execution; nested inclusive times must not be summed.',
            'Fresh processes, not cold OS/file caches. No CPU isolation, fixed clock, network/server-capacity, side-channel or security proof. All runs retained.']}
    (args.out/'lifecycle.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    if drift: raise RuntimeError('source drift during lifecycle measurement')

if __name__=='__main__': main()
