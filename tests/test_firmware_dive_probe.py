"""Bounded fixture-only probes: exact authority, no network, stable receipts."""
import dataclasses
import json
import os
import pathlib
import signal
import sqlite3
import sys

from types import SimpleNamespace
import pytest

from audit_core import firmware_dive_acquisition as acq
from tests.test_firmware_chain_validation import graph_case, prepared  # noqa: F401
from tests.test_firmware_dive_prepare import canonical, sha, prepare, rows, files, manifest as questions_manifest
from tests.test_firmware_dive_questions import entry
from tests.test_firmware_dive_snapshot import snapshot
from tests.test_firmware_dive_snapshot import complete
from tests.test_hunt_gate import state


@pytest.fixture
def probe(graph_case, tmp_path, monkeypatch):
    complete(graph_case)
    generation = prepare(graph_case, questions_path=questions_manifest(tmp_path, [entry(snapshot(graph_case)) | {"method":"emulate"}]))
    question = next(r for r in rows(graph_case[0], 'cba_firmware_dive_questions') if r['method'] == 'emulate')
    packet = json.loads((graph_case[1] / question['packet_path']).read_bytes())
    spec = dict(schema_version=1, image_id='target', dive_generation=generation.dive_generation,
        question_id=question['question_id'], packet_sha256=question['packet_sha256'],
        contract_sha256=sha(canonical(packet['acquisition_contract'])), method='emulate', executable='a',
        runner=None, loader=None, libraries=[], nvram_shim=None, argv=['a'], environment={}, stdin=None,
        inputs=[], outputs=[], isolation_backend='bwrap', adapter_path=None, network_policy='none', timeout_seconds=2)
    path = tmp_path / 'probe.json'
    path.write_bytes(canonical(spec))
    # The fixture adapter runs only purpose-built Python test programs. It never
    # executes the corpus bytes in root/a and never attempts network operations.
    monkeypatch.setattr(acq, '_select_adapter', lambda spec: None, raising=False)
    # Darwin has no enforceable aggregate/address-space limit. Production
    # probes fail closed there; purpose-built fixture programs exercise the
    # remaining containment and receipt path without corpus execution.
    monkeypatch.setattr(acq, '_memory_limits_available', lambda: True)
    return graph_case, path, spec


def save(probe):
    probe[1].write_bytes(canonical(probe[2]))


def run(probe, con=None):
    case, path, _ = probe
    return acq.run_probe(con or case[0], case[1], case[2], path)


def manifest(summary):
    return json.loads(pathlib.Path(summary.manifest_path).read_bytes())


class FixtureAdapter:
    backend = 'bwrap'
    path = pathlib.Path(sys.executable).resolve()

    def __init__(self, program):
        self.program = program

    def command(self, spec, staging, output):
        program = 'import os; os.environ.clear(); os.environ.update('+repr(dict(spec.environment))+')\n'+self.program
        return [str(self.path), '-I', '-S', '-c', program, str(staging), str(output), *spec.argv]


def test_probe_refuses_when_memory_containment_is_unavailable(probe, monkeypatch):
    monkeypatch.setattr(acq, '_select_adapter', lambda spec: FixtureAdapter('pass'))
    monkeypatch.setattr(acq, '_memory_limits_available', lambda: False)
    monkeypatch.setattr(acq.subprocess, 'Popen',
                        lambda *a, **k: pytest.fail('memory-unbounded firmware invoked'))
    summary = run(probe)
    value = manifest(summary)
    assert not value['termination']['executed']
    assert value['termination']['reason'] == 'unsupported-limits'


def executable(probe, monkeypatch, program):
    monkeypatch.setattr(acq, '_select_adapter', lambda spec: FixtureAdapter(program))


def test_unavailable_seals_exact_identity_without_subprocess_or_conclusion(probe, monkeypatch):
    monkeypatch.setattr(acq.subprocess, 'Popen', lambda *a, **k: pytest.fail('firmware invoked'))
    before = {t: rows(probe[0][0], t) for t in ('cba_firmware_dive_questions', 'cba_firmware_dive_observations',
        'cba_firmware_dive_receipts', 'cba_firmware_findings')}
    summary = run(probe)
    value = manifest(summary)
    assert summary.kind == 'probe' and summary.file_count == 2 and summary.byte_count == 0
    assert value['termination'] == dict(executed=False, reason='isolation-unavailable', exit_code=None,
        signal=None, timed_out=False, stdout_truncated=False, stderr_truncated=False,
        adapter_exit_code=None, adapter_signal=None, status_source='direct-process')
    assert value['network_policy'] == 'none' and value['dependencies'][0]['path'] == 'a'
    assert value['dependencies'][0]['before'] == value['dependencies'][0]['after']
    assert value['spec']['stdout_bytes'] == value['spec']['stderr_bytes'] == 1048576
    assert value['spec']['output_bytes'] == 8388608 and value['spec']['output_files'] == 256
    assert b'conclusion' not in pathlib.Path(summary.manifest_path).read_bytes()
    assert str(probe[0][2]) not in pathlib.Path(summary.manifest_path).read_text()
    identity = value.pop('acquisition_id')
    assert sha(canonical(value)) == identity == summary.acquisition_id
    assert all(rows(probe[0][0], t) == prior for t, prior in before.items())
    with pytest.raises(dataclasses.FrozenInstanceError): acq.load_probe_spec(probe[1]).method = 'static'
    with pytest.raises(dataclasses.FrozenInstanceError): acq.ProbeTermination(False, 'x', None, None, False, False, False).reason = 'y'


@pytest.mark.parametrize('field,value', [('extra',0), ('schema_version',True), ('method','hardware'),
    ('network_policy','host'), ('timeout_seconds',0), ('timeout_seconds',301), ('timeout_seconds',True),
    ('argv',[]), ('argv',['other']), ('argv',['a']*129), ('argv',['a','x'*4097]), ('argv',['a','\x00']),
    ('environment',{'PATH':'/bin'}), ('environment',{'LD_PRELOAD':'x'}), ('environment',{'DYLD_INSERT_LIBRARIES':'x'}),
    ('environment',{'lower':'x'}), ('environment',{'X':0}), ('environment',{'X':'x'*4097}),
    ('environment',{f'X{i}':'x' for i in range(65)}), ('executable','/bin/x'), ('executable','../x'),
    ('libraries',['b','a']), ('libraries',['a','a']), ('inputs',['./a']), ('outputs',['../x']),
    ('outputs',['/x']), ('outputs',['a','a/b']), ('outputs',['a','a']), ('outputs',['x']*257),
    ('runner','python'), ('adapter_path','bwrap'), ('isolation_backend','docker'), ('stdin',False),
    ('loader','../x'), ('nvram_shim','/x'), ('image_id',''), ('contract_sha256','A'*64)])
def test_strict_wire_rejects_unsafe_or_unbounded_probe(probe, field, value):
    probe[2][field] = value
    save(probe)
    before, artifacts = state(probe[0][0]), files(probe[0][1])
    with pytest.raises(acq.AcquisitionError): acq.load_probe_spec(probe[1])
    with pytest.raises(acq.AcquisitionError): run(probe)
    assert state(probe[0][0]) == before and files(probe[0][1]) == artifacts


@pytest.mark.parametrize('damage', ['duplicate', 'nonfinite', 'oversize', 'deep', 'not-object', 'missing'])
def test_malformed_probe_json(probe, damage):
    if damage == 'duplicate': raw = canonical(probe[2])[:-1] + b',"method":"emulate"}'
    elif damage == 'nonfinite': raw = canonical(probe[2]).replace(b'"schema_version":1',b'"schema_version":NaN')
    elif damage == 'oversize': raw = b' '*1048577
    elif damage == 'deep': raw = b'['*2000+b'0'+b']'*2000
    elif damage == 'not-object': raw = b'[]'
    else:
        del probe[2]['method']
        raw = canonical(probe[2])
    probe[1].write_bytes(raw)
    with pytest.raises(acq.AcquisitionError): run(probe)


@pytest.mark.parametrize('field', ['image_id','dive_generation','question_id','packet_sha256','contract_sha256'])
def test_probe_requires_exact_prepared_owner(probe, field):
    probe[2][field] = 'foreign' if field == 'image_id' else '0'*64
    save(probe)
    before, artifacts = state(probe[0][0]), files(probe[0][1])
    with pytest.raises(acq.AcquisitionError): run(probe)
    assert state(probe[0][0]) == before and files(probe[0][1]) == artifacts


def test_controlled_process_minimal_environment_closed_fds_and_streams(probe, monkeypatch):
    probe[2].update(stdin='b', inputs=['c'], libraries=['b'], loader='c', nvram_shim='a',
        runner=str(pathlib.Path(sys.executable).resolve()),
        environment={'TOKEN':'literal $() ;'}, outputs=['result'])
    save(probe)
    program = "import os,sys,pathlib,json; p=pathlib.Path(sys.argv[2]); p.joinpath('result').write_text(json.dumps(dict(env=dict(os.environ),sid=os.getsid(0),pid=os.getpid(),stdin=sys.stdin.read()))); print('out'); print('err',file=sys.stderr)"
    executable(probe, monkeypatch, program)
    summary = run(probe)
    value = manifest(summary)
    assert value['termination'] == dict(executed=True, reason='exited', exit_code=0, signal=None,
        timed_out=False, stdout_truncated=False, stderr_truncated=False,
        adapter_exit_code=None, adapter_signal=None, status_source='direct-process')
    base = pathlib.Path(summary.manifest_path).parent
    assert (base/'evidence/stdout').read_bytes() == b'out\n'
    assert (base/'evidence/stderr').read_bytes() == b'err\n'
    result = json.loads((base/'outputs/result').read_bytes())
    assert result['sid'] == result['pid']
    assert result['env']['TOKEN'] == 'literal $() ;' and 'PATH' not in result['env']
    assert set(result['env']) <= {'TOKEN','LD_PRELOAD','LC_CTYPE','__CF_USER_TEXT_ENCODING'}
    assert result['stdin'] == (probe[0][2]/'b').read_text()
    assert {d['role'] for d in value['dependencies']} == {'executable','stdin','input','library','loader','nvram-shim','runner','adapter'}
    assert all(d['before'] == d['after'] for d in value['dependencies'])


@pytest.mark.parametrize('program,reason,code,sig', [("raise SystemExit(7)",'exited',7,None),
    ("import os,signal; os.kill(os.getpid(),signal.SIGTERM)",'signal',None,signal.SIGTERM),
    ("import time; time.sleep(10)",'timeout',None,signal.SIGKILL)])
def test_exit_signal_and_timeout_are_facts(probe, monkeypatch, program, reason, code, sig):
    probe[2]['timeout_seconds'] = 1
    save(probe)
    executable(probe, monkeypatch, program)
    term = manifest(run(probe))['termination']
    assert term['reason'] == reason and term['exit_code'] == code and term['signal'] == sig
    assert term['timed_out'] == (reason == 'timeout')


def test_flooded_streams_are_bounded_and_explicit(probe, monkeypatch):
    executable(probe, monkeypatch, "import os; os.write(1,b'x'*1100000); os.write(2,b'y'*1100000)")
    summary = run(probe)
    value = manifest(summary)
    assert value['termination']['stdout_truncated'] and value['termination']['stderr_truncated']
    assert summary.byte_count == 2097152
    assert all(r['byte_count'] == 1048576 for r in value['evidence'])


@pytest.mark.parametrize('program', ["p.joinpath('other').write_bytes(b'x')", "p.joinpath('wanted').symlink_to('/etc/passwd')",
    "import os; os.mkfifo(p/'wanted')", "p.joinpath('wanted').mkdir()", "p.joinpath('wanted').write_bytes(b'x'*8388609)"])
def test_hostile_output_attempts_are_blocked_or_bounded_without_conclusions(probe, monkeypatch, program):
    probe[2]['outputs'] = ['wanted']
    save(probe)
    executable(probe, monkeypatch, "import pathlib,sys; p=pathlib.Path(sys.argv[2]); "+program)
    value=manifest(run(probe))
    assert value['termination']['exit_code'] != 0
    assert all(e['path'] in ('evidence/stdout','evidence/stderr','outputs/wanted') for e in value['evidence'])
    assert sum(e['byte_count'] for e in value['evidence'] if e['path'].startswith('outputs/'))<=8388608
    assert rows(probe[0][0],'cba_firmware_dive_observations')==[]


def test_duplicate_is_no_write(probe):
    first = run(probe)
    before, writes, artifacts = state(probe[0][0]), probe[0][0].total_changes, files(probe[0][1])
    assert run(probe) == first
    assert state(probe[0][0]) == before and probe[0][0].total_changes == writes and files(probe[0][1]) == artifacts


def test_post_run_source_drift_refuses(probe, monkeypatch):
    class Drift(FixtureAdapter):
        def command(self, spec, staging, output):
            (probe[0][2]/'a').write_bytes(b'changed')
            return super().command(spec, staging, output)
    monkeypatch.setattr(acq, '_select_adapter', lambda spec: Drift('print(1)'))
    before = state(probe[0][0])
    with pytest.raises(acq.AcquisitionError): run(probe)
    assert state(probe[0][0]) == before


def test_publication_failure_retains_no_sql(probe, monkeypatch):
    before = state(probe[0][0])
    monkeypatch.setattr(acq.db, 'put', lambda *a, **k: (_ for _ in ()).throw(sqlite3.OperationalError('fail')))
    with pytest.raises(acq.AcquisitionError): run(probe)
    assert state(probe[0][0]) == before and not probe[0][0].in_transaction


def test_caller_transaction_preserved(probe):
    probe[0][0].execute('BEGIN')
    with pytest.raises(acq.AcquisitionError): run(probe)
    assert probe[0][0].in_transaction
    probe[0][0].rollback()


def test_shared_reader_ctime_detects_same_inode_size_restored_mtime(tmp_path, monkeypatch):
    from audit_core import firmware_dive as dive
    import contextlib
    path = tmp_path/'source'
    path.write_bytes(b'first')
    before = path.stat()
    original = os.fstat
    calls = 0
    def rewrite(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            path.write_bytes(b'other')
            os.utime(path, ns=(before.st_atime_ns,before.st_mtime_ns))
        return original(fd)
    monkeypatch.setattr(dive.os, 'fstat', rewrite)
    with contextlib.ExitStack() as stack:
        parent = dive._directory(tmp_path, stack)
        with pytest.raises(dive.FirmwareDiveError): dive._read_regular(parent,'source',5)
    after = path.stat()
    assert (before.st_ino,before.st_size,before.st_mtime_ns) == (after.st_ino,after.st_size,after.st_mtime_ns)
    assert before.st_ctime_ns != after.st_ctime_ns


def test_nested_outputs_preserve_paths_and_reject_undeclared_nested_entries(probe, monkeypatch):
    probe[2]['outputs'] = ['dir/sub/result']
    save(probe)
    executable(probe, monkeypatch, "import pathlib,sys; pathlib.Path(sys.argv[2],'dir/sub/result').write_bytes(b'fixture')")
    summary = run(probe)
    assert (pathlib.Path(summary.manifest_path).parent/'outputs/dir/sub/result').read_bytes() == b'fixture'
    executable(probe, monkeypatch, "import pathlib,sys; pathlib.Path(sys.argv[2],'dir/sub/unknown').write_bytes(b'fixture')")
    value=manifest(run(probe))
    assert value['termination']['exit_code'] != 0
    assert not any(e['path'].startswith('outputs/') for e in value['evidence'])


def test_inheritable_host_descriptor_is_closed(probe, monkeypatch):
    fd = os.open(probe[1],os.O_RDONLY)
    try:
        os.set_inheritable(fd,True)
        executable(probe,monkeypatch,f"import os\ntry: os.fstat({fd})\nexcept OSError: print('closed')\nelse: raise SystemExit(9)")
        summary = run(probe)
        assert manifest(summary)['termination']['exit_code'] == 0
        assert (pathlib.Path(summary.manifest_path).parent/'evidence/stdout').read_bytes() == b'closed\n'
    finally:
        os.close(fd)


def test_descendant_holding_pipes_is_killed_at_deadline(probe, monkeypatch, tmp_path):
    # NPROC is per-UID, so the developer host may already exceed 64. This
    # one-child fixture isolates group cleanup; a separate real child pins all
    # production rlimits, including NPROC=64. No firmware/tool is run here.
    def fixture_limits():
        acq.resource.setrlimit(acq.resource.RLIMIT_FSIZE,(8388608,8388608))
        acq.resource.setrlimit(acq.resource.RLIMIT_NOFILE,(64,64))
    monkeypatch.setattr(acq,'_child_limits',fixture_limits)
    pidfile = tmp_path/'pid'
    # Host path is used only by this purpose-built injected fixture to observe
    # cleanup, never passed to or executed by a real isolation adapter.
    executable(probe,monkeypatch,"import os,time,pathlib; pid=os.fork(); pathlib.Path("+repr(str(pidfile))+").write_text(str(pid)) if pid else time.sleep(10)")
    probe[2]['timeout_seconds'] = 1
    save(probe)
    summary = run(probe)
    assert manifest(summary)['termination']['timed_out']
    pid = int(pidfile.read_text())
    import time
    for _ in range(100):
        try: os.kill(pid,0)
        except ProcessLookupError: break
        time.sleep(.01)
    else: pytest.fail('descendant survived process-group cleanup')


@pytest.mark.parametrize('damage', ['unknown','wrong-platform','missing','symlink','unready','not-executable'])
def test_adapter_refusals_never_launch_firmware(probe, monkeypatch, tmp_path, damage):
    # Restore the real selector, bypassed by the ownership fixture above.
    # Restore the production selector saved before the fixture overrides it.
    monkeypatch.setattr(acq,'_select_adapter',REAL_SELECT_ADAPTER)
    path = tmp_path/'bwrap'
    path.write_bytes(b'fixture adapter')
    path.chmod(0o700)
    probe[2]['adapter_path'] = str(path)
    monkeypatch.setattr(acq.sys,'platform','linux')
    if damage == 'unknown':
        probe[2]['adapter_path'] = str(tmp_path/'renamed')
    elif damage == 'wrong-platform': monkeypatch.setattr(acq.sys,'platform','darwin')
    elif damage == 'missing': path.unlink()
    elif damage == 'symlink':
        path.unlink(); path.symlink_to(probe[1])
    elif damage == 'not-executable': path.chmod(0o600)
    def readiness(command, environment, stdin, timeout, cwd, **kwargs):
        assert pathlib.Path(command[0]).name=='bwrap' and command[0]!=str(path)
        assert '--unshare-all' in command and '--proc' in command
        assert pathlib.Path(command[0]).read_bytes()==b'fixture adapter'
        return acq.ProbeTermination(True,'exited',1,None,False,False,False),b'',b''
    monkeypatch.setattr(acq,'_process',readiness)
    # macOS has no /proc: emulate only the fixed host namespace metadata read.
    stat = acq.os.stat
    monkeypatch.setattr(acq.os,'stat',lambda p,*a,**k: type('Namespace',(),{'st_ino':1})() if str(p)=='/proc/self/ns/net' else stat(p,*a,**k))
    save(probe)
    value = manifest(run(probe))
    assert not value['termination']['executed'] and value['termination']['reason'] == 'isolation-unavailable'


REAL_SELECT_ADAPTER = acq._select_adapter


def test_known_adapter_commands_never_mount_host_linux_runtime(tmp_path):
    spec = dict(schema_version=1,image_id='x',dive_generation='a'*64,question_id='b'*64,
        packet_sha256='c'*64,contract_sha256='d'*64,method='emulate',executable='bin/app',
        runner='/usr/local/qemu',loader='lib/ld.so',libraries=['lib/libc.so'],nvram_shim=None,
        argv=['bin/app','a;$(literal)'],environment={},stdin=None,inputs=['etc/config'],outputs=['result'],
        isolation_backend='bwrap',adapter_path=None,network_policy='none',timeout_seconds=1)
    parsed = acq._probe_parse(canonical(spec))
    command = acq._IsolationAdapter('bwrap',pathlib.Path('/usr/bin/bwrap')).command(parsed,tmp_path/'firmware',tmp_path/'output')
    assert command[:4] == ['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session']
    binds = [command[i+1:i+3] for i,word in enumerate(command) if word=='--ro-bind']
    assert [str(tmp_path/'firmware/bin/app'),'/bin/app'] in binds
    assert ['/lib','/lib'] not in binds and ['/usr/lib','/usr/lib'] not in binds
    assert command[-1] == 'a;$(literal)' and '--library-path' in command
    mac = acq._IsolationAdapter('sandbox-exec',pathlib.Path('/usr/bin/sandbox-exec')).command(parsed,tmp_path/'firmware',tmp_path/'output')
    assert '(deny network*)' in mac[2] and '(deny process-fork)' in mac[2]
    assert '(allow process-exec)' in mac[2] and '(allow default)' not in mac[2]


def test_static_runner_requires_valid_elf_without_interpreter():
    import struct
    static = bytearray(64)
    static[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<Q',static,32,64)
    struct.pack_into('<HH',static,54,56,0)
    assert acq._static_runner(bytes(static))
    dynamic = static+bytearray(56)
    struct.pack_into('<H',dynamic,56,1)
    struct.pack_into('<I',dynamic,64,3)
    assert not acq._static_runner(bytes(dynamic))
    assert not acq._static_runner(b'script')
    assert not acq._static_runner(bytes(dynamic[:70]))


def test_symlink_stdin_is_never_followed(tmp_path):
    target = tmp_path/'secret'
    target.write_bytes(b'secret')
    link = tmp_path/'stdin'
    link.symlink_to(target)
    with pytest.raises((acq.AcquisitionError, acq.dive.FirmwareDiveError)):
        acq._process([sys.executable,'-I','-c','import sys; print(sys.stdin.read())'],{},link,1,tmp_path)


@pytest.mark.parametrize('failure', ['commit','unexpected','lock'])
def test_probe_publication_rolls_back_and_preserves_siblings(probe, monkeypatch, failure):
    case = probe[0]
    before = state(case[0])
    connection = case[0]
    if failure == 'commit':
        class Connection(sqlite3.Connection):
            def commit(self): raise sqlite3.OperationalError('injected commit failure')
        connection = sqlite3.connect(case[1]/'audit.db',factory=Connection)
        connection.row_factory = sqlite3.Row
    elif failure == 'unexpected':
        monkeypatch.setattr(acq.db,'put',lambda *a,**k: (_ for _ in ()).throw(RuntimeError('unexpected')))
    else:
        connection = sqlite3.connect(case[1]/'audit.db',timeout=0)
        connection.row_factory = sqlite3.Row
        case[0].execute('BEGIN IMMEDIATE')
    try:
        with pytest.raises(RuntimeError if failure=='unexpected' else acq.AcquisitionError): run(probe,connection)
        assert state(case[0]) == before and not connection.in_transaction
    finally:
        if failure == 'lock': case[0].rollback()
        if connection is not case[0]: connection.close()


@pytest.mark.parametrize('damage',['row','foreign-owner','manifest','extra','output-link'])
def test_probe_conflicting_duplicate_refuses_without_repair(probe,monkeypatch,tmp_path,damage):
    probe[2]['outputs'] = ['dir/result']
    save(probe)
    executable(probe,monkeypatch,"import pathlib,sys; pathlib.Path(sys.argv[2],'dir/result').write_bytes(b'exact')")
    first = run(probe)
    directory = pathlib.Path(first.manifest_path).parent
    if damage == 'row': probe[0][0].execute("UPDATE cba_firmware_dive_acquisitions SET details='{}'")
    elif damage == 'foreign-owner': probe[0][0].execute("UPDATE cba_firmware_dive_acquisitions SET image_id='foreign'")
    elif damage == 'manifest': (directory/'manifest.json').write_bytes(b'drift')
    elif damage == 'extra': (directory/'extra').write_bytes(b'new')
    else:
        (directory/'outputs/dir/result').unlink()
        external=tmp_path/'external';external.write_bytes(b'exact')
        (directory/'outputs/dir/result').symlink_to(external)
    probe[0][0].commit()
    before = state(probe[0][0])
    with pytest.raises(acq.AcquisitionError):run(probe)
    assert state(probe[0][0]) == before


@pytest.mark.parametrize('damage',['input','spec','installed','question'])
def test_locked_probe_revalidation_catches_drift(probe,monkeypatch,damage):
    install=acq.dive._install
    before=state(probe[0][0])
    def race(destination,contents,run_dir):
        install(destination,contents,run_dir)
        if damage=='input': (probe[0][2]/'a').write_bytes(b'changed')
        elif damage=='spec': probe[1].write_bytes(canonical(probe[2]|{'timeout_seconds':3}))
        elif damage=='installed': (destination/'evidence/stdout').write_bytes(b'changed')
        else:
            probe[0][0].execute("UPDATE cba_firmware_dive_questions SET question='changed' WHERE question_id=?",(probe[2]['question_id'],))
            probe[0][0].commit()
    monkeypatch.setattr(acq.dive,'_install',race)
    with pytest.raises(acq.AcquisitionError):run(probe)
    assert not probe[0][0].in_transaction and rows(probe[0][0],'cba_firmware_dive_acquisitions')==[]
    if damage!='question':assert state(probe[0][0])==before


def test_tool_launch_absence_is_a_fact_and_stream_error_is_not_a_receipt(tmp_path,monkeypatch):
    term,out,err=acq._process(['/no-such-purpose-fixture'],{},None,1,tmp_path)
    assert not term.executed and term.reason=='tool-unavailable' and out==err==b''
    original=acq.os.read
    monkeypatch.setattr(acq.os,'read',lambda fd,n: (_ for _ in ()).throw(OSError('pipe failure')) if not os.get_blocking(fd) else original(fd,n))
    with pytest.raises(OSError):acq._process([sys.executable,'-I','-c','print(1)'],{},None,1,tmp_path)
    monkeypatch.setattr(acq.os,'read',original)


def test_cleanup_failure_never_publishes(probe,monkeypatch):
    executable(probe,monkeypatch,'print(1)')
    before=state(probe[0][0])
    monkeypatch.setattr(acq,'_kill_group',lambda process: (_ for _ in ()).throw(PermissionError('injected')))
    with pytest.raises(acq.AcquisitionError):run(probe)
    assert state(probe[0][0])==before


@pytest.mark.parametrize('boundary',['bytes','files'])
def test_exact_output_limits_are_accepted(probe,monkeypatch,boundary):
    if boundary=='bytes':
        probe[2]['outputs']=['result']
        program="import pathlib,sys; pathlib.Path(sys.argv[2],'result').write_bytes(b'x'*8388608)"
    else:
        probe[2]['outputs']=[f'{n:03}' for n in range(256)]
        program="import pathlib,sys; p=pathlib.Path(sys.argv[2]); [(p/f'{n:03}').write_bytes(b'x') for n in range(256)]"
    save(probe)
    executable(probe,monkeypatch,program)
    summary=run(probe)
    assert summary.byte_count==(8388608 if boundary=='bytes' else 256)
    assert summary.file_count==(3 if boundary=='bytes' else 258)


def test_host_runner_local_path_does_not_change_identity(probe,tmp_path):
    original=pathlib.Path(sys.executable).resolve()
    probe[2]['runner']=str(original)
    save(probe)
    first=run(probe)
    copied=tmp_path/'explicit-runner';copied.write_bytes(original.read_bytes())
    probe[2]['runner']=str(copied)
    save(probe)
    before,writes,artifacts=state(probe[0][0]),probe[0][0].total_changes,files(probe[0][1])
    assert run(probe)==first
    assert state(probe[0][0])==before and probe[0][0].total_changes==writes and files(probe[0][1])==artifacts
    raw=pathlib.Path(first.manifest_path).read_bytes()
    assert str(original).encode() not in raw and str(copied).encode() not in raw


def test_ready_supported_adapter_is_hash_stable_and_readiness_is_fixed(probe,monkeypatch,tmp_path):
    path=tmp_path/'sandbox-exec';path.write_bytes(b'operator-trusted fixture');path.chmod(0o700)
    probe[2].update(adapter_path=str(path),isolation_backend='sandbox-exec')
    save(probe)
    monkeypatch.setattr(acq.sys,'platform','darwin')
    monkeypatch.setattr(acq,'_select_adapter',REAL_SELECT_ADAPTER)
    def ready(command,environment,stdin,timeout,cwd, **kwargs):
        assert command[0]==str(path) and '(deny network*)' in command[2]
        assert environment=={} and stdin is None and timeout==3
        return acq.ProbeTermination(True,'exited',0,None,False,False,False),b'',b''
    monkeypatch.setattr(acq,'_process',ready)
    adapter=REAL_SELECT_ADAPTER(acq.load_probe_spec(probe[1]))
    assert adapter is not None and adapter.path==path
    assert acq._adapter_ready(adapter)
    path.write_bytes(b'changed after readiness')
    with pytest.raises(acq.AcquisitionError):acq._probe_inputs(probe[1],probe[0][2],adapter)


def test_runner_unsupported_is_a_nonexecuted_fact(probe,monkeypatch):
    probe[2]['runner']=str(pathlib.Path(sys.executable).resolve())
    save(probe)
    # The adapter is known/injected as ready; no real external tool is invoked.
    adapter=acq._IsolationAdapter('bwrap',pathlib.Path(sys.executable).resolve())
    monkeypatch.setattr(acq,'_select_adapter',lambda spec:adapter)
    monkeypatch.setattr(acq.subprocess,'Popen',lambda *a,**k:pytest.fail('unsupported runner invoked'))
    value=manifest(run(probe))
    assert value['termination']['reason']=='unsupported-runner' and not value['termination']['executed']


@pytest.mark.parametrize('count',[256,257])
def test_probe_staged_dependencies_bound_exact_count(probe,tmp_path,count):
    root=tmp_path/'bounded-root';root.mkdir()
    for n in range(count):(root/f'{n:03}').write_bytes(b'x')
    probe[2].update(executable='000',argv=['000'],libraries=[f'{n:03}' for n in range(1,count)])
    save(probe)
    if count>256:
        with pytest.raises(acq.AcquisitionError):acq._probe_inputs(probe[1],root)
    else:
        assert len(acq._probe_inputs(probe[1],root)[3])==256


def test_readiness_timeout_with_zero_parent_exit_is_unavailable(probe,monkeypatch,tmp_path):
    path=tmp_path/'sandbox-exec';path.write_bytes(b'fixture');path.chmod(0o700)
    probe[2].update(adapter_path=str(path),isolation_backend='sandbox-exec');save(probe)
    monkeypatch.setattr(acq.sys,'platform','darwin')
    monkeypatch.setattr(acq,'_process',lambda *a,**k:(acq.ProbeTermination(True,'timeout',0,None,True,False,False),b'',b''))
    assert not acq._adapter_ready(REAL_SELECT_ADAPTER(acq.load_probe_spec(probe[1])))


def test_zombie_group_permission_does_not_hide_live_cleanup_failure(monkeypatch):
    import types
    monkeypatch.setattr(acq.os,'killpg',lambda *a:(_ for _ in ()).throw(PermissionError('kernel zombie group')))
    with pytest.raises(PermissionError):acq._kill_group(types.SimpleNamespace(pid=123,poll=lambda:None))
    acq._kill_group(types.SimpleNamespace(pid=123,poll=lambda:0))


def test_static_elf_32_big_endian_and_bounded_headers():
    import struct
    raw=bytearray(84);raw[:7]=b'\x7fELF\x01\x02\x01'
    struct.pack_into('>I',raw,28,52);struct.pack_into('>HH',raw,42,32,1);struct.pack_into('>I',raw,52,1)
    assert acq._static_runner(bytes(raw))
    short=bytearray(52);short[:7]=b'\x7fELF\x02\x01\x01'
    assert not acq._static_runner(bytes(short))
    struct.pack_into('>H',raw,44,65535)
    assert not acq._static_runner(bytes(raw))


def test_output_file_count_overflow_is_never_collected(probe,monkeypatch):
    probe[2]['outputs']=[f'{n:03}' for n in range(256)];save(probe)
    executable(probe,monkeypatch,"import pathlib,sys; p=pathlib.Path(sys.argv[2]); [(p/f'{n:03}').write_bytes(b'x') for n in range(257)]")
    value=manifest(run(probe))
    assert value['termination']['exit_code'] != 0
    assert len([e for e in value['evidence'] if e['path'].startswith('outputs/')])==256
    assert not any(e['path']=='outputs/256' for e in value['evidence'])


def test_closed_streams_still_enforce_process_timeout(probe,monkeypatch):
    probe[2]['timeout_seconds']=1;save(probe)
    executable(probe,monkeypatch,'import os,time; os.close(1); os.close(2); time.sleep(10)')
    term=manifest(run(probe))['termination']
    assert term['timed_out'] and term['signal']==signal.SIGKILL


def test_stuck_pipe_readiness_has_bounded_cleanup_failure(probe,monkeypatch):
    import time
    probe[2]['timeout_seconds']=1;save(probe)
    executable(probe,monkeypatch,'import time; time.sleep(10)')
    selector=acq.selectors.DefaultSelector
    class Stuck(selector):
        def select(self,timeout=None):
            time.sleep(.01)
            return []
    monkeypatch.setattr(acq.selectors,'DefaultSelector',Stuck)
    before=state(probe[0][0])
    with pytest.raises(acq.AcquisitionError):run(probe)
    assert state(probe[0][0])==before


def test_hardware_question_cannot_gain_probe_authority(probe,monkeypatch):
    question=next(r for r in rows(probe[0][0],'cba_firmware_dive_questions') if r['method']=='hardware')
    packet=json.loads((probe[0][1]/question['packet_path']).read_bytes())
    probe[2].update(question_id=question['question_id'],packet_sha256=question['packet_sha256'],
        contract_sha256=sha(canonical(packet['acquisition_contract'])))
    save(probe)
    executable(probe,monkeypatch,'raise SystemExit(99)')
    before=state(probe[0][0])
    with pytest.raises(acq.AcquisitionError):run(probe)
    assert state(probe[0][0])==before


def test_adapter_replacement_between_verification_and_exec_cannot_change_invoked_bytes(probe,monkeypatch,tmp_path):
    path=tmp_path/'sandbox-exec';path.write_bytes(b'verified adapter bytes');path.chmod(0o700)
    probe[2].update(adapter_path=str(path),isolation_backend='sandbox-exec');save(probe)
    monkeypatch.setattr(acq,'_select_adapter',REAL_SELECT_ADAPTER)
    monkeypatch.setattr(acq.sys,'platform','darwin')
    observed=[]
    def readiness(command,environment,stdin,timeout,cwd, **kwargs):
        path.write_bytes(b'replaced host adapter')
        observed.append(pathlib.Path(command[0]).read_bytes())
        assert observed[-1]==b'verified adapter bytes'
        return acq.ProbeTermination(True,'exited',1,None,False,False,False),b'',b''
    monkeypatch.setattr(acq,'_process',readiness)
    before=state(probe[0][0])
    with pytest.raises(acq.AcquisitionError):run(probe)
    assert observed==[b'verified adapter bytes'] and state(probe[0][0])==before


def test_unproduced_declared_output_remains_a_fact(probe,monkeypatch):
    probe[2]['outputs']=['optional'];save(probe)
    executable(probe,monkeypatch,'print("fixture")')
    value=manifest(run(probe))
    assert value['spec']['outputs']==['optional']
    assert [item['path'] for item in value['evidence']]==['evidence/stderr','evidence/stdout']
    assert value['termination']['exit_code']==0


def test_mac_manifest_records_fixed_system_runtime_limit(probe):
    probe[2]['isolation_backend']='sandbox-exec';save(probe)
    value=manifest(run(probe))
    assert value['runtime']['system_read_roots']==['/System','/usr/lib','/private/var/db/dyld','/dev/null','/dev/urandom']
    assert value['runtime']['limitation']=='Apple system runtime reads are not firmware library evidence'
    assert value['runtime']['platform']==sys.platform and value['runtime']['version']
    assert not value['termination']['executed']


@pytest.mark.parametrize('backend,platform_name,want',[('bwrap','linux','/usr/bin/bwrap'),('sandbox-exec','darwin','/usr/bin/sandbox-exec')])
def test_discovery_uses_fixed_literals_without_ambient_path(probe,monkeypatch,backend,platform_name,want):
    probe[2]['isolation_backend']=backend
    spec=acq._probe_parse(canonical(probe[2]))
    monkeypatch.setattr(acq.sys,'platform',platform_name)
    opened=[]
    def source(path,maximum):
        opened.append(str(path));return b'fixture',(1,2,3,4,5,6)
    monkeypatch.setattr(acq,'_source',source)
    monkeypatch.setattr(acq.os,'access',lambda *a:True)
    selected=REAL_SELECT_ADAPTER(spec)
    assert selected.path==pathlib.Path(want) and opened==[want]


@pytest.mark.parametrize('tamper',[None,'readiness','firmware'])
def test_known_adapter_readiness_and_execution_use_same_private_ordinary_copy(probe,monkeypatch,tmp_path,tamper):
    path=tmp_path/'sandbox-exec';path.write_bytes(b'fixture adapter');path.chmod(0o4700)
    probe[2].update(adapter_path=str(path),isolation_backend='sandbox-exec');save(probe)
    monkeypatch.setattr(acq.sys,'platform','darwin')
    monkeypatch.setattr(acq,'_select_adapter',REAL_SELECT_ADAPTER)
    commands=[]
    def process(command,environment,stdin,timeout,cwd, **kwargs):
        executable_path=pathlib.Path(command[0]);commands.append(command)
        assert command[0]!=str(path) and executable_path.name=='sandbox-exec'
        assert executable_path.read_bytes()==b'fixture adapter'
        assert executable_path.stat().st_mode & 0o7777==0o500
        if len(commands)==1:
            assert '(deny network*)' in command[2] and timeout==3
        else:
            assert '(deny default)' in command[2] and '(deny process-fork)' in command[2]
            assert command[0]==commands[0][0]
        if tamper==('readiness' if len(commands)==1 else 'firmware'):
            executable_path.chmod(0o700);executable_path.write_bytes(b'drift')
        return acq.ProbeTermination(True,'exited',0,None,False,False,False),b'fixture',b''
    monkeypatch.setattr(acq,'_process',process)
    before=state(probe[0][0])
    if tamper:
        with pytest.raises(acq.AcquisitionError):run(probe)
        assert state(probe[0][0])==before
    else:
        value=manifest(run(probe))
        assert value['termination']['executed'] and len(commands)==2
        assert 'trusted tooling' in value['runtime']['tool_runtime_limitation']


def test_unavailable_namespace_readiness_seals_without_process(probe,monkeypatch,tmp_path):
    path=tmp_path/'bwrap';path.write_bytes(b'fixture adapter');path.chmod(0o700)
    probe[2].update(adapter_path=str(path),isolation_backend='bwrap');save(probe)
    monkeypatch.setattr(acq.sys,'platform','linux')
    monkeypatch.setattr(acq,'_select_adapter',REAL_SELECT_ADAPTER)
    stat=acq.os.stat
    def no_namespace(p,*a,**k):
        if str(p)=='/proc/self/ns/net':raise FileNotFoundError('namespace introspection absent')
        return stat(p,*a,**k)
    monkeypatch.setattr(acq.os,'stat',no_namespace)
    monkeypatch.setattr(acq.subprocess,'Popen',lambda *a,**k:pytest.fail('unready adapter invoked'))
    term=manifest(run(probe))['termination']
    assert not term['executed'] and term['reason']=='isolation-unavailable'


def test_shim_is_never_injected_into_host_adapter_environment(probe,monkeypatch,tmp_path):
    native_helper(monkeypatch)
    path=tmp_path/'sandbox-exec';path.write_bytes(b'fixture adapter');path.chmod(0o700)
    probe[2].update(adapter_path=str(path),isolation_backend='sandbox-exec',nvram_shim='a');save(probe)
    monkeypatch.setattr(acq.sys,'platform','darwin')
    monkeypatch.setattr(acq,'_select_adapter',REAL_SELECT_ADAPTER)
    calls=[]
    def process(command,environment,stdin,timeout,cwd, **kwargs):
        calls.append(command)
        assert 'LD_PRELOAD' not in environment and 'DYLD_INSERT_LIBRARIES' not in environment
        if len(calls)==2:
            assert any(arg.startswith('DYLD_INSERT_LIBRARIES=') for arg in command)
            assert pathlib.Path(command[3]).name=='_environment-launcher'
        return acq.ProbeTermination(True,'exited',0,None,False,False,False),b'',b''
    monkeypatch.setattr(acq,'_process',process)
    value=manifest(run(probe))
    assert value['termination']['executed'] and len(calls)==2
    assert 'environment-launcher' in {d['role'] for d in value['dependencies']}


def test_bwrap_shim_environment_is_set_inside_the_namespace(probe,tmp_path):
    probe[2].update(nvram_shim='a',environment={'TOKEN':'literal ; $()'})
    spec=acq._probe_parse(canonical(probe[2]))
    command=acq._IsolationAdapter('bwrap',pathlib.Path('/usr/bin/bwrap')).command(spec,tmp_path,tmp_path)
    environment={command[i+1]:command[i+2] for i,arg in enumerate(command) if arg=='--setenv'}
    assert environment=={'LD_PRELOAD':'/a','TOKEN':'literal ; $()'} and '--clearenv' in command


def test_declared_environment_reaches_guest_only(probe,monkeypatch,tmp_path):
    native_helper(monkeypatch)
    path=tmp_path/'sandbox-exec';path.write_bytes(b'fixture adapter');path.chmod(0o700)
    probe[2].update(adapter_path=str(path),isolation_backend='sandbox-exec',environment={'TOKEN':'literal $() ;'})
    save(probe)
    monkeypatch.setattr(acq.sys,'platform','darwin');monkeypatch.setattr(acq,'_select_adapter',REAL_SELECT_ADAPTER)
    calls=[]
    def process(command,environment,stdin,timeout,cwd, **kwargs):
        assert environment=={}
        calls.append(command)
        if len(calls)==2:assert 'TOKEN=literal $() ;' in command
        return acq.ProbeTermination(True,'exited',0,None,False,False,False),b'',b''
    monkeypatch.setattr(acq,'_process',process)
    assert manifest(run(probe))['termination']['executed'] and len(calls)==2


def native_helper(monkeypatch):
    import struct
    raw=bytearray(32);raw[:4]=b'\xcf\xfa\xed\xfe'
    cpu=0x100000c if acq.platform.machine() in ('arm64','aarch64') else 0x1000007
    struct.pack_into('<I',raw,4,cpu)
    monkeypatch.setattr(acq,'_environment_launcher',lambda:(bytes(raw),(1,2,0o100755,32,4,5)))


@pytest.mark.parametrize('when',['before','after'])
def test_helper_source_drift_never_becomes_false_execution_facts(probe,monkeypatch,tmp_path,when):
    native_helper(monkeypatch)
    path=tmp_path/'sandbox-exec';path.write_bytes(b'fixture adapter');path.chmod(0o700)
    probe[2].update(adapter_path=str(path),isolation_backend='sandbox-exec',environment={'TOKEN':'safe'});save(probe)
    monkeypatch.setattr(acq.sys,'platform','darwin');monkeypatch.setattr(acq,'_select_adapter',REAL_SELECT_ADAPTER)
    calls=[]
    def process(command,environment,stdin,timeout,cwd, **kwargs):
        calls.append(command)
        if len(calls)==(1 if when=='before' else 2):
            monkeypatch.setattr(acq,'_environment_launcher',lambda:(b'drifted helper',(1,2,0o100755,14,6,7)))
        return acq.ProbeTermination(True,'exited',0,None,False,False,False),b'',b''
    monkeypatch.setattr(acq,'_process',process)
    before=state(probe[0][0])
    if when=='after':
        with pytest.raises(acq.AcquisitionError):run(probe)
        assert len(calls)==2 and state(probe[0][0])==before
    else:
        value=manifest(run(probe))
        assert not value['termination']['executed'] and value['termination']['reason']=='unsupported-helper'
        helper=next(d for d in value['dependencies'] if d['role']=='environment-launcher')
        assert helper['before']!=helper['after'] and helper['after']['sha256']==sha(b'drifted helper')
        assert len(calls)==1


@pytest.mark.parametrize('helper',[None,b'not native Mach-O'])
def test_unavailable_or_incompatible_environment_launcher_never_executes(probe,monkeypatch,tmp_path,helper):
    path=tmp_path/'sandbox-exec';path.write_bytes(b'fixture adapter');path.chmod(0o700)
    probe[2].update(adapter_path=str(path),isolation_backend='sandbox-exec',environment={'TOKEN':'safe'});save(probe)
    monkeypatch.setattr(acq.sys,'platform','darwin');monkeypatch.setattr(acq,'_select_adapter',REAL_SELECT_ADAPTER)
    monkeypatch.setattr(acq,'_environment_launcher',lambda:(helper,(1,2,0o100755,16,4,5) if helper else None))
    monkeypatch.setattr(acq,'_process',lambda *a:pytest.fail('unsupported helper invoked'))
    value=manifest(run(probe))
    assert not value['termination']['executed'] and value['termination']['reason']=='unsupported-helper'
    fact=next(d for d in value['dependencies'] if d['role']=='environment-launcher')
    assert fact['path'] is None and fact['before']==fact['after']


@pytest.mark.parametrize('failure',['missing','nonexecutable','valid'])
def test_fixed_environment_launcher_is_read_without_path_lookup(monkeypatch,failure):
    opened=[]
    def source(path,maximum):
        opened.append(path)
        if failure=='missing':raise FileNotFoundError('missing')
        return b'native bytes',(1,2,0o100755 if failure=='valid' else 0o100644,12,4,5)
    monkeypatch.setattr(acq,'_source',source)
    value=acq._environment_launcher()
    assert opened==['/usr/bin/env']
    assert value[0]==(b'native bytes' if failure=='valid' else None)


def test_environment_launcher_compatibility_has_bounded_native_headers(monkeypatch):
    import struct
    monkeypatch.setattr(acq.platform,'machine',lambda:'arm64')
    native=bytearray(32);native[:4]=b'\xcf\xfa\xed\xfe';struct.pack_into('<I',native,4,0x100000c)
    assert acq._compatible_environment_launcher(bytes(native))
    assert not acq._compatible_environment_launcher(bytes(native[:8]))
    wrong=bytearray(native);struct.pack_into('<I',wrong,4,0x1000007)
    assert not acq._compatible_environment_launcher(bytes(wrong))
    fat=bytearray(48);fat[:4]=b'\xca\xfe\xba\xbe';struct.pack_into('>I',fat,4,2)
    struct.pack_into('>I',fat,8,0x1000007);struct.pack_into('>I',fat,28,0x100000c)
    assert acq._compatible_environment_launcher(bytes(fat))
    assert not acq._compatible_environment_launcher(bytes(fat[:20]))
    struct.pack_into('>I',fat,4,33)
    assert not acq._compatible_environment_launcher(bytes(fat))


def test_staged_environment_launcher_drift_refuses_before_payload(probe,monkeypatch,tmp_path):
    native_helper(monkeypatch)
    path=tmp_path/'sandbox-exec';path.write_bytes(b'fixture adapter');path.chmod(0o700)
    probe[2].update(adapter_path=str(path),isolation_backend='sandbox-exec',environment={'TOKEN':'safe'});save(probe)
    monkeypatch.setattr(acq.sys,'platform','darwin');monkeypatch.setattr(acq,'_select_adapter',REAL_SELECT_ADAPTER)
    calls=[]
    def process(command,*args,**kwargs):
        calls.append(command)
        helper=pathlib.Path(command[0]).parent.parent/'firmware/_environment-launcher'
        helper.chmod(0o700);helper.write_bytes(b'staged drift')
        return acq.ProbeTermination(True,'exited',0,None,False,False,False),b'',b''
    monkeypatch.setattr(acq,'_process',process)
    before=state(probe[0][0])
    with pytest.raises(acq.AcquisitionError):run(probe)
    assert len(calls)==1 and state(probe[0][0])==before


def test_output_aggregate_growth_is_terminated_during_execution(probe, monkeypatch):
    import time
    probe[2].update(outputs=['first','second'], timeout_seconds=5)
    save(probe)
    executable(probe,monkeypatch,"import pathlib,sys,time; p=pathlib.Path(sys.argv[2]); p.joinpath('first').write_bytes(b'x'*5000000); p.joinpath('second').write_bytes(b'y'*5000000); time.sleep(10)")
    started=time.monotonic()
    value=manifest(run(probe))
    assert value['termination']['reason']=='output-limit'
    assert not value['termination']['timed_out'] and time.monotonic()-started<4
    assert sum(e['byte_count'] for e in value['evidence'])<=2*acq.MAX_PROBE_STREAM_BYTES
    assert rows(probe[0][0],'cba_firmware_dive_observations')==[]


def test_output_tree_mutation_is_terminated_during_execution(probe, monkeypatch):
    import time
    probe[2].update(outputs=['dir/result'], timeout_seconds=5)
    save(probe)
    executable(probe,monkeypatch,"import pathlib,sys,time; p=pathlib.Path(sys.argv[2]); p.chmod(0o700); p.joinpath('undeclared').write_bytes(b'x'); time.sleep(10)")
    started=time.monotonic()
    value=manifest(run(probe))
    assert value['termination']['reason']=='output-limit'
    assert not value['termination']['timed_out'] and time.monotonic()-started<4


def test_output_files_are_precreated_and_only_exact_files_are_writable(probe, monkeypatch, tmp_path):
    probe[2]['outputs']=['dir/result'];save(probe)
    executable(probe,monkeypatch,"import pathlib,sys; p=pathlib.Path(sys.argv[2]); assert p.stat().st_mode&0o222==0; assert p.joinpath('dir').stat().st_mode&0o222==0; assert p.joinpath('dir/result').read_bytes()==b''; p.joinpath('dir/result').write_bytes(b'ok')")
    value=manifest(run(probe))
    assert value['termination']['exit_code']==0
    spec=acq.load_probe_spec(probe[1])
    command=acq._IsolationAdapter('bwrap',pathlib.Path('/usr/bin/bwrap')).command(spec,tmp_path/'firmware',tmp_path/'output')
    readonly=[command[i+1:i+3] for i,arg in enumerate(command) if arg=='--ro-bind']
    assert [str(tmp_path/'output'),'/output'] in readonly
    binds=[command[i+1:i+3] for i,arg in enumerate(command) if arg=='--bind']
    assert binds==[[str(tmp_path/'output/dir/result'),'/output/dir/result']]
    assert '--cap-drop' in command and command[command.index('--cap-drop')+1]=='ALL'
    mac=acq._IsolationAdapter('sandbox-exec',pathlib.Path('/usr/bin/sandbox-exec')).command(spec,tmp_path/'firmware',tmp_path/'output')
    assert '(literal '+json.dumps(str(tmp_path/'output/dir/result'))+')' in mac[2]
    assert '(allow file-write* (subpath '+json.dumps(str(tmp_path/'output'))+')' not in mac[2]


def test_child_resource_limits_are_fixed_and_inherited(tmp_path):
    import resource
    names=('RLIMIT_FSIZE','RLIMIT_NPROC','RLIMIT_NOFILE')
    program='import json,resource; print(json.dumps([resource.getrlimit(getattr(resource,k)) for k in '+repr(names)+']))'
    termination,out,_=acq._process([sys.executable,'-I','-S','-c',program],{},None,2,tmp_path)
    assert termination.exit_code==0
    assert json.loads(out)==[[8388608,8388608],
                             [acq.MAX_PROBE_PROCESSES]*2,[64,64]]


def test_unavailable_child_limits_refuse_before_subprocess(tmp_path, monkeypatch):
    import resource
    monkeypatch.delattr(resource,'RLIMIT_NPROC')
    monkeypatch.setattr(acq.subprocess,'Popen',lambda *a,**k:pytest.fail('unbounded process invoked'))
    termination,out,err=acq._process([sys.executable,'-I','-c','print(1)'],{},None,2,tmp_path)
    assert not termination.executed and termination.reason=='unsupported-limits'
    assert out==err==b''


@pytest.mark.parametrize('produce',[False,True])
def test_precreated_placeholder_is_absent_but_explicit_empty_output_is_produced(probe, monkeypatch, produce):
    probe[2]['outputs']=['result'];save(probe)
    executable(probe,monkeypatch,"import pathlib,sys; p=pathlib.Path(sys.argv[2],'result'); "+("p.write_bytes(b'')" if produce else 'pass'))
    value=manifest(run(probe))
    outputs=[e for e in value['evidence'] if e['path'].startswith('outputs/')]
    assert outputs==([{'path':'outputs/result','sha256':sha(b''),'byte_count':0}] if produce else [])


@pytest.mark.parametrize('failure',['root','low-hard-limit','get-failure','missing-module'])
def test_unenforceable_child_limits_seal_unsupported(tmp_path, monkeypatch, failure):
    if failure=='root':monkeypatch.setattr(acq.os,'getuid',lambda:0)
    elif failure=='low-hard-limit':monkeypatch.setattr(acq.resource,'getrlimit',lambda _: (1,1))
    elif failure=='get-failure':monkeypatch.setattr(acq.resource,'getrlimit',lambda _: (_ for _ in ()).throw(OSError('unsupported')))
    else:monkeypatch.setattr(acq,'resource',None)
    monkeypatch.setattr(acq.subprocess,'Popen',lambda *a,**k:pytest.fail('unenforceable child invoked'))
    term,out,err=acq._process([sys.executable,'-I','-c','pass'],{},None,1,tmp_path)
    assert not term.executed and term.reason=='unsupported-limits' and out==err==b''


def test_output_fsize_signal_is_an_output_limit_fact(probe, monkeypatch):
    probe[2]['outputs']=['result'];save(probe)
    executable(probe,monkeypatch,"import os,pathlib,signal,sys; signal.signal(signal.SIGXFSZ,signal.SIG_DFL); f=os.open(pathlib.Path(sys.argv[2],'result'),os.O_WRONLY); os.write(f,b'x'*8388608); os.write(f,b'x')")
    value=manifest(run(probe))
    assert value['termination']['reason']=='output-limit' and value['termination']['signal']==signal.SIGXFSZ
    assert not any(e['path'].startswith('outputs/') for e in value['evidence'])


def test_empty_output_ctime_change_is_produced_even_with_restored_mtime(probe, monkeypatch):
    probe[2]['outputs']=['result'];save(probe)
    executable(probe,monkeypatch,"import os,pathlib,sys; p=pathlib.Path(sys.argv[2],'result'); before=p.stat(); p.write_bytes(b''); os.utime(p,ns=(before.st_atime_ns,before.st_mtime_ns)); assert p.stat().st_ctime_ns!=before.st_ctime_ns")
    value=manifest(run(probe))
    assert value['termination']['exit_code']==0
    assert [e for e in value['evidence'] if e['path'].startswith('outputs/')]==[{'path':'outputs/result','sha256':sha(b''),'byte_count':0}]
@pytest.mark.parametrize('case,expected', [
    ('nonlinux', False), ('missing', False), ('failure', False),
    ('low', False), ('exact', True), ('infinite', True),
])
def test_memory_limit_support_is_explicit_and_fail_closed(monkeypatch, case, expected):
    platform = 'darwin' if case == 'nonlinux' else 'linux'
    monkeypatch.setattr(acq.sys, 'platform', platform)
    if case == 'missing':
        fake = SimpleNamespace()
    else:
        def getrlimit(_):
            if case == 'failure':
                raise OSError('unsupported')
            hard = {'low': acq.MAX_PROBE_ADDRESS_BYTES - 1,
                    'exact': acq.MAX_PROBE_ADDRESS_BYTES,
                    'infinite': -1}.get(case, acq.MAX_PROBE_ADDRESS_BYTES)
            return 0, hard
        fake = SimpleNamespace(RLIMIT_AS=1, RLIM_INFINITY=-1, getrlimit=getrlimit)
    monkeypatch.setattr(acq, 'resource', fake)
    assert acq._memory_limits_available() is expected


def test_linux_child_limits_include_address_space(monkeypatch):
    calls = []
    monkeypatch.setattr(acq.sys, 'platform', 'linux')
    monkeypatch.setattr(acq.resource, 'setrlimit',
                        lambda key, value: calls.append((key, value)))
    acq._child_limits()
    assert calls[0] == (acq.resource.RLIMIT_AS,
                        (acq.MAX_PROBE_ADDRESS_BYTES,) * 2)




def test_child_limit_setup_failure_cannot_execute_payload(tmp_path, monkeypatch):
    marker=tmp_path/'executed'
    def unavailable(): raise OSError('limit enforcement unavailable')
    monkeypatch.setattr(acq,'_child_limits',unavailable)
    term,out,err=acq._process([sys.executable,'-I','-c','import pathlib; pathlib.Path('+repr(str(marker))+').write_text("wrong")'],{},None,1,tmp_path)
    assert not term.executed and term.reason=='unsupported-limits'
    assert not marker.exists() and out==err==b''


def test_child_limit_syscalls_apply_the_fixed_hard_and_soft_bounds(monkeypatch):
    calls=[]
    monkeypatch.setattr(acq.resource,'setrlimit',lambda key,value:calls.append((key,value)))
    acq._child_limits()
    expected=[(acq.resource.RLIMIT_FSIZE,(8388608,8388608)),
              (acq.resource.RLIMIT_NPROC,(acq.MAX_PROBE_PROCESSES,)*2),
              (acq.resource.RLIMIT_NOFILE,(64,64))]
    if sys.platform.startswith('linux'):
        expected.insert(0,(acq.resource.RLIMIT_AS,(acq.MAX_PROBE_ADDRESS_BYTES,)*2))
    assert calls==expected


@pytest.mark.parametrize('damage',['mode','extra','missing','symlink','directory-replaced','file-replaced','hardlink','oversize','stat-error'])
def test_output_guard_detects_bounded_shape_size_and_inode_changes(tmp_path, monkeypatch, damage):
    import contextlib
    output=tmp_path/'output';output.mkdir()
    acq._prepare_outputs(output,('dir/result',))
    with contextlib.ExitStack() as stack:
        guard=acq._output_guard(output,('dir/result',),stack)
        assert guard()
        output.chmod(0o700);(output/'dir').chmod(0o700)
        target=output/'dir/result'
        if damage=='mode':pass
        elif damage=='extra':(output/'extra').write_bytes(b'x')
        elif damage=='missing':target.unlink()
        elif damage=='symlink':target.unlink();target.symlink_to('/etc/passwd')
        elif damage=='directory-replaced':
            (output/'dir').rename(tmp_path/'old');(output/'dir').mkdir();(output/'dir/result').write_bytes(b'')
        elif damage=='file-replaced':
            replacement=tmp_path/'replacement';replacement.write_bytes(b'');os.replace(replacement,target)
        elif damage=='hardlink':os.link(target,tmp_path/'linked')
        elif damage=='oversize':
            with target.open('wb') as stream:stream.truncate(8388609)
        else:
            original=acq.os.stat
            def missing(path,*a,**k):
                if str(path)=='result':raise OSError('injected descriptor stat failure')
                return original(path,*a,**k)
            monkeypatch.setattr(acq.os,'stat',missing)
        if damage!='mode':
            output.chmod(0o500);(output/'dir').chmod(0o500)
        if damage=='directory-replaced':(tmp_path/'old').chmod(0o500)
        assert not guard()
    output.chmod(0o700);(output/'dir').chmod(0o700)
    if damage=='directory-replaced':(tmp_path/'old').chmod(0o700)


def test_missing_resource_module_imports_as_unsupported(monkeypatch):
    import builtins,importlib.util
    name='audit_core._probe_missing_resource_fixture'
    spec=importlib.util.spec_from_file_location(name,acq.__file__)
    module=importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules,name,module)
    original=builtins.__import__
    def without_resource(name,*a,**k):
        if name=='resource':raise ImportError('unsupported host')
        return original(name,*a,**k)
    monkeypatch.setattr(builtins,'__import__',without_resource)
    spec.loader.exec_module(module)
    assert module.resource is None and not module._limits_available()


def test_bwrap_implicit_root_and_virtual_mounts_are_read_only(probe, tmp_path):
    probe[2]['outputs']=['dir/result']
    spec=acq._probe_parse(canonical(probe[2]))
    command=acq._IsolationAdapter('bwrap',pathlib.Path('/usr/bin/bwrap')).command(spec,tmp_path/'firmware',tmp_path/'output')
    assert [command[i+1] for i,arg in enumerate(command) if arg=='--remount-ro']==['/','/dev','/proc']
    assert command.index('--dev')<command.index('--remount-ro')<command.index('--bind')
    assert command[command.index('--bind')+1:command.index('--bind')+3]==[str(tmp_path/'output/dir/result'),'/output/dir/result']


@pytest.mark.parametrize('known',[False,True])
def test_probe_preserves_unsupported_limits_before_adapter_readiness(probe, monkeypatch, known):
    adapter=(acq._IsolationAdapter('sandbox-exec',pathlib.Path(sys.executable).resolve()) if known else FixtureAdapter('print(1)'))
    monkeypatch.setattr(acq,'_select_adapter',lambda _:adapter)
    monkeypatch.setattr(acq,'resource',None)
    monkeypatch.setattr(acq,'_process',lambda *a,**k:pytest.fail('readiness or firmware started without limits'))
    value=manifest(run(probe))
    assert not value['termination']['executed'] and value['termination']['reason']=='unsupported-limits'


def test_bwrap_readiness_requires_the_payload_readonly_and_capability_controls(monkeypatch,tmp_path):
    adapter=acq._IsolationAdapter('bwrap',tmp_path/'bwrap')
    original=acq.os.stat
    monkeypatch.setattr(acq.os,'stat',lambda p,*a,**k:type('Namespace',(),{'st_ino':1})() if str(p)=='/proc/self/ns/net' else original(p,*a,**k))
    def process(command,environment,stdin,timeout,cwd):
        assert [command[i+1] for i,arg in enumerate(command) if arg=='--remount-ro']==['/','/dev','/proc']
        assert command[command.index('--cap-drop')+1]=='ALL'
        return acq.ProbeTermination(True,'exited',0,None,False,False,False),b'',b''
    monkeypatch.setattr(acq,'_process',process)
    assert acq._adapter_ready(adapter)


def test_bwrap_requires_non_optional_user_namespace_and_disables_nested_namespaces(probe,monkeypatch,tmp_path):
    spec=acq.load_probe_spec(probe[1])
    adapter=acq._IsolationAdapter('bwrap',tmp_path/'bwrap')
    command=adapter.command(spec,tmp_path/'firmware',tmp_path/'output')
    assert '--unshare-user' in command and '--disable-userns' in command
    original=acq.os.stat
    monkeypatch.setattr(acq.os,'stat',lambda p,*a,**k:type('Namespace',(),{'st_ino':1})() if str(p)=='/proc/self/ns/net' else original(p,*a,**k))
    def readiness(command,environment,stdin,timeout,cwd):
        assert '--unshare-user' in command and '--disable-userns' in command
        return acq.ProbeTermination(True,'exited',0,None,False,False,False),b'',b''
    monkeypatch.setattr(acq,'_process',readiness)
    assert acq._adapter_ready(adapter)


def test_bwrap_unsupported_namespace_controls_refuse_without_retry_or_payload(probe,monkeypatch,tmp_path):
    path=tmp_path/'bwrap';path.write_bytes(b'operator-trusted fixture');path.chmod(0o700)
    probe[2].update(adapter_path=str(path),isolation_backend='bwrap');save(probe)
    monkeypatch.setattr(acq,'_select_adapter',REAL_SELECT_ADAPTER)
    monkeypatch.setattr(acq.sys,'platform','linux')
    original=acq.os.stat
    monkeypatch.setattr(acq.os,'stat',lambda p,*a,**k:type('Namespace',(),{'st_ino':1})() if str(p)=='/proc/self/ns/net' else original(p,*a,**k))
    calls=[]
    def unsupported(command,environment,stdin,timeout,cwd,**kwargs):
        calls.append(command)
        assert '--unshare-user' in command and '--disable-userns' in command
        return acq.ProbeTermination(True,'exited',1,None,False,False,False),b'',b'unsupported option'
    monkeypatch.setattr(acq,'_process',unsupported)
    value=manifest(run(probe))
    assert len(calls)==1
    assert not value['termination']['executed'] and value['termination']['reason']=='isolation-unavailable'
    assert value['spec']['user_namespace_policy']=='isolated-nested-disabled'
    assert not any(e['path'].startswith('outputs/') for e in value['evidence'])


def native_status_fixture(probe,monkeypatch,backend,program):
    """Exercise native-adapter status handling with bounded Python fixtures only."""
    probe[2].update(isolation_backend=backend,outputs=['result']);save(probe)
    monkeypatch.setattr(acq,'_select_adapter',lambda _:acq._IsolationAdapter(backend,pathlib.Path(sys.executable).resolve()))
    monkeypatch.setattr(acq,'_adapter_ready',lambda _:True)
    monkeypatch.setattr(acq._IsolationAdapter,'command',lambda self,spec,staging,output:
        [str(pathlib.Path(sys.executable).resolve()),'-I','-S','-c',program,str(output/'result')])


@pytest.mark.parametrize('backend',['bwrap','sandbox-exec'])
@pytest.mark.parametrize('origin,code',[('encoded-fsize',153),('encoded-term',143),('voluntary-matching',153)])
def test_native_adapter_encoded_and_voluntary_statuses_cannot_claim_payload_termination(probe,monkeypatch,backend,origin,code):
    # The one-child fixture mimics wrapper wait-status translation. NPROC is
    # per UID and already exceeded on this host; only this fixture omits it.
    # The production hard/soft limit is independently tested with a real child.
    def fixture_limits():
        acq.resource.setrlimit(acq.resource.RLIMIT_FSIZE,(8388608,8388608))
        acq.resource.setrlimit(acq.resource.RLIMIT_NOFILE,(64,64))
    monkeypatch.setattr(acq,'_child_limits',fixture_limits)
    program='''import os,signal,sys
pid=os.fork()
if pid==0:
    f=os.open(sys.argv[1],os.O_WRONLY)
    if ORIGIN=='encoded-fsize':
        signal.signal(signal.SIGXFSZ,signal.SIG_DFL)
        os.write(f,b'x'*8388608)
        os.write(f,b'x')
    else:
        os.write(f,b'prefix')
        if ORIGIN=='encoded-term':os.kill(os.getpid(),signal.SIGTERM)
        else:os._exit(153)
    os._exit(99)
_,status=os.waitpid(pid,0)
code=os.waitstatus_to_exitcode(status)
os._exit(128-code if code<0 else code)
'''.replace('ORIGIN',repr(origin))
    native_status_fixture(probe,monkeypatch,backend,program)
    value=manifest(run(probe))
    term=value['termination']
    assert term['exit_code'] is None and term['signal'] is None
    assert term['reason']=='adapter-exited' and term['adapter_exit_code']==code and term['adapter_signal'] is None
    assert term['status_source']==backend+'-adapter'
    assert value['runtime']['stream_source']==backend+'-adapter'
    assert not any(e['path'].startswith('outputs/') for e in value['evidence'])
    assert rows(probe[0][0],'cba_firmware_dive_observations')==[]


@pytest.mark.parametrize('backend',['bwrap','sandbox-exec'])
@pytest.mark.parametrize('outcome',['zero','nonzero','signal'])
def test_native_adapter_observed_status_is_separate_and_only_zero_keeps_outputs(probe,monkeypatch,backend,outcome):
    end={'zero':'raise SystemExit(0)','nonzero':'raise SystemExit(7)',
        'signal':'os.kill(os.getpid(),signal.SIGTERM)'}[outcome]
    native_status_fixture(probe,monkeypatch,backend,"import os,pathlib,signal,sys; pathlib.Path(sys.argv[1]).write_bytes(b'checked'); "+end)
    value=manifest(run(probe));term=value['termination']
    assert term['exit_code'] is None and term['signal'] is None
    assert term['status_source']==backend+'-adapter'
    if outcome=='signal':
        assert term['reason']=='adapter-signal' and term['adapter_exit_code'] is None and term['adapter_signal']==15
    else:
        assert term['reason']=='adapter-exited' and term['adapter_exit_code']==(0 if outcome=='zero' else 7) and term['adapter_signal'] is None
    outputs=[e['path'] for e in value['evidence'] if e['path'].startswith('outputs/')]
    assert outputs==(['outputs/result'] if outcome=='zero' else [])


@pytest.mark.parametrize('reason',['timeout','output-limit'])
def test_native_ambiguous_zero_wrapper_status_does_not_publish_partial_outputs(probe,monkeypatch,reason):
    native_status_fixture(probe,monkeypatch,'bwrap','pass')
    def stopped(command,environment,stdin,timeout,cwd,**kwargs):
        (cwd/'result').write_bytes(b'partial')
        return acq.ProbeTermination(True,reason,0,None,reason=='timeout',False,False),b'wrapper-stream',b''
    monkeypatch.setattr(acq,'_process',stopped)
    value=manifest(run(probe));term=value['termination']
    assert term['reason']==reason and term['adapter_exit_code']==0
    assert term['exit_code'] is None and term['signal'] is None
    assert value['runtime']['stream_source']=='bwrap-adapter'
    assert not any(e['path'].startswith('outputs/') for e in value['evidence'])
