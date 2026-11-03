"""Seal question-owned hardware bytes and bounded isolated single-binary facts.

Source paths and timestamps never establish acquisition identity. Receipts do
not answer questions, create findings or select evidence rungs.
"""
from __future__ import annotations

import contextlib
import dataclasses
import json
import pathlib
import sqlite3
import os
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import struct
import platform
import stat
try:
    import resource
except ImportError:
    resource = None

from audit_core import db, firmware_chain, firmware_fpcheck, surface
from audit_core import firmware_dive as dive
from audit_core import firmware_dive_questions as q
from audit_core.firmware_dive_questions import AcquisitionContract

MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_FILES = 256
MAX_SPEC_BYTES = 1024 * 1024


class AcquisitionError(Exception):
    """Exact question ownership, stable bytes or atomic publication failed."""


@dataclasses.dataclass(frozen=True, slots=True)
class CaptureSpec:
    schema_version: int
    image_id: str
    dive_generation: str
    question_id: str
    packet_sha256: str
    contract_sha256: str
    device_identifier: str
    firmware_version: str
    firmware_sha256: str
    lifecycle: str
    posture: str
    authentication: str
    operator: str
    source: str
    method: str
    evidence: tuple[tuple[str, str], ...]


@dataclasses.dataclass(frozen=True, slots=True)
class AcquisitionSummary:
    image_id: str
    dive_generation: str
    question_id: str
    acquisition_id: str
    kind: str
    spec_path: str
    manifest_path: str
    file_count: int
    byte_count: int


def _require(value, message):
    if not value:
        raise AcquisitionError(message)


def _source(path, maximum):
    path = dive._selector(path)
    with contextlib.ExitStack() as stack:
        parent = dive._directory(path.parent, stack)
        return dive._read_regular(parent, path.name, maximum)


def _parse(raw):
    value = json.loads(raw, object_pairs_hook=q._pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(AcquisitionError('Non-finite capture JSON')))
    q._object(value, CaptureSpec)
    _require(type(value['schema_version']) is int and value['schema_version'] == 1, 'Invalid capture schema')
    image = value['image_id']
    _require(isinstance(image, str) and bool(image.strip()) and '\x00' not in image and
        len(image.encode('utf-8')) <= 4096, 'Invalid capture image identity')
    for key in ('device_identifier','firmware_version','operator','source'):
        q._text(value[key], key)
    for key in ('dive_generation','question_id','packet_sha256','contract_sha256','firmware_sha256'):
        q._digest(value[key])
    for key, states in (('lifecycle',db.FIRMWARE_CHAIN_LIFECYCLE_STATES),
            ('posture',db.FIRMWARE_CHAIN_POSTURE_STATES), ('authentication',db.FIRMWARE_CHAIN_AUTH_STATES)):
        q._enum(value[key], states)
    q._enum(value['method'], ('hardware',))
    evidence = value['evidence']
    _require(isinstance(evidence, list) and 1 <= len(evidence) <= MAX_CAPTURE_FILES, 'Invalid capture file count')
    parsed = []
    for item in evidence:
        _require(isinstance(item, dict) and set(item) == {'name','source_path'}, 'Invalid evidence schema')
        name, source = item['name'], item['source_path']
        q._relative(name)
        q._relative(source)
        q._text(name, 'evidence name', 255)
        q._text(source, 'source path')
        _require('/' not in name, 'Evidence name must be a flat basename')
        parsed.append((name, source))
    _require(parsed == sorted(parsed) and len({name for name,_ in parsed}) == len(parsed),
        'Evidence names require sorted unique entries')
    return CaptureSpec(**(value | dict(evidence=tuple(parsed))))


def load_capture_spec(path) -> CaptureSpec:
    """Load a bounded strict spec; paths resolve relative to its no-follow parent."""
    try:
        return _parse(_source(path, MAX_SPEC_BYTES)[0])
    except (OSError, ValueError, TypeError, KeyError, RecursionError,
            dive.FirmwareDiveError, q.FirmwareDiveQuestionError) as exc:
        raise AcquisitionError('Cannot load capture specification') from exc


def _inputs(path):
    raw, identity = _source(path, MAX_SPEC_BYTES)
    spec = _parse(raw)
    contents, sources, total = {}, [], 0
    for name, relative in spec.evidence:
        evidence, signature = _source(pathlib.Path(path).parent / relative, MAX_CAPTURE_BYTES - total)
        total += len(evidence)
        contents['evidence/' + name] = evidence
        sources.append((relative, signature, evidence))
    return spec, raw, identity, tuple(sources), contents


def _ownership(con, run, root, spec):
    graph = firmware_chain.verified_retained_graph_snapshot(con, run, root,
        image_id=spec.image_id, dive_generation=spec.dive_generation)
    rows = dive._rows(con, spec.image_id)
    dive._history(run, rows, graph)
    owners = [row for row in rows['runs'] if row['dive_generation'] == spec.dive_generation]
    assignments = [row for row in rows['questions'] if
        (row['dive_generation'],row['question_id']) == (spec.dive_generation,spec.question_id)]
    _require(len(owners) == len(assignments) == 1, 'Capture requires exactly one prepared question')
    row, = assignments
    raw = dive._read(run, row['packet_path'], row['packet_sha256'], q.MAX_PACKET_BYTES)
    packet = dive._json(raw)
    contract = packet['acquisition_contract']
    _require(row['packet_sha256'] == spec.packet_sha256 and q._hash(contract) == spec.contract_sha256,
        'Capture packet or contract differs')
    question = dive._question(packet['question'])
    expected = json.loads(q.packet_bytes(question, graph))['acquisition_contract']
    _require(contract == expected and contract['image_id'] == spec.image_id and
        contract['question_id'] == spec.question_id and contract['method'] == spec.method == 'hardware' and
        contract['artifact_kinds'] == ['hardware-capture'] and
        contract['acquisition_class'] == 'external-hardware-capture' and
        contract['max_files'] == MAX_CAPTURE_FILES and contract['max_capture_bytes'] == MAX_CAPTURE_BYTES,
        'Capture exceeds exact question acquisition authority')
    dive._extracts(run, question.extract_records)
    return graph, rows, raw


def _build(run, inputs):
    spec, _, _, sources, contents = inputs
    sealed = dataclasses.asdict(spec) | dict(evidence=[name for name,_ in spec.evidence])
    evidence = [dict(name=name, sha256=dive._digest(contents['evidence/' + name]),
        byte_count=len(contents['evidence/' + name])) for name,_ in spec.evidence]
    identity = q._hash(dict(kind='capture', spec=sealed, evidence=evidence))
    manifest = sealed | dict(kind='capture', acquisition_id=identity, evidence=evidence)
    contents = contents | {'spec.json':q._bytes(sealed), 'manifest.json':q._bytes(manifest)}
    relative = 'artifacts/firmware-dive-captures/' + identity
    total = sum(len(raw) for _,_,raw in sources)
    summary = AcquisitionSummary(spec.image_id, spec.dive_generation, spec.question_id, identity, 'capture',
        str(run / relative / 'spec.json'), str(run / relative / 'manifest.json'), len(evidence), total)
    record = dict(image_id=spec.image_id, dive_generation=spec.dive_generation, question_id=spec.question_id,
        acquisition_id=identity, kind='capture', contract_sha256=spec.contract_sha256,
        spec_path=relative + '/spec.json', spec_sha256=dive._digest(contents['spec.json']),
        manifest_path=relative + '/manifest.json', manifest_sha256=dive._digest(contents['manifest.json']),
        evidence_paths=q._bytes(sorted([relative + '/evidence/' + row['name'] for row in evidence], key=q._bytes)).decode(),
        details=q._bytes(dict(kind='capture', byte_count=total, file_count=len(evidence))).decode())
    return summary, contents, record


def seal_capture(con, run_dir, root, spec_path) -> AcquisitionSummary:
    """Install stable bytes first, then repeat authority and byte checks under lock."""
    started = False
    try:
        _require(not con.in_transaction, 'Capture sealing requires no active transaction')
        run, path = dive._selector(run_dir), dive._selector(spec_path)
        inputs = _inputs(path)
        con.execute('BEGIN')
        started = True
        ownership = _ownership(con, run, root, inputs[0])
        con.rollback()
        started = False
        summary, contents, record = _build(run, inputs)
        destination = pathlib.Path(summary.manifest_path).parent
        dive._install(destination, contents, run)
        con.execute('BEGIN IMMEDIATE')
        started = True
        _require(_inputs(path) == inputs and _ownership(con, run, root, inputs[0]) == ownership,
            'Capture inputs changed before publication')
        dive._checked_install(destination, contents, run)
        prior = surface._query(con, 'SELECT * FROM cba_firmware_dive_acquisitions WHERE acquisition_id=?',
            (summary.acquisition_id,))
        if prior:
            _require(len(prior) == 1 and all(prior[0][key] == value for key,value in record.items()),
                'Existing capture ownership differs')
        else:
            db.put(con, 'cba_firmware_dive_acquisitions', record, commit=False)
        con.commit()
        started = False
        return summary
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc, (sqlite3.Error, db.DbError)):
            raise AcquisitionError('database operation failed') from exc
        if isinstance(exc, (OSError, ValueError, TypeError, KeyError, RecursionError,
                dive.FirmwareDiveError, q.FirmwareDiveQuestionError,
                firmware_chain.FirmwareChainError, firmware_fpcheck.FpcheckError, surface.SurfaceError)):
            raise AcquisitionError('Cannot seal hardware capture') from exc
        raise


# Probe wire limits are fixed by the prepared acquisition contract. Dependency
# reads have an additional memory bound; they are never obtained via PATH.
MAX_PROBE_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_PROBE_STREAM_BYTES = 1024 * 1024
MAX_DEPENDENCY_BYTES = 64 * 1024 * 1024
MAX_PROBE_ADDRESS_BYTES = 256 * 1024 * 1024
MAX_PROBE_PROCESSES = 4


@dataclasses.dataclass(frozen=True, slots=True)
class ProbeSpec:
    schema_version: int
    image_id: str
    dive_generation: str
    question_id: str
    packet_sha256: str
    contract_sha256: str
    method: str
    executable: str
    runner: str | None
    loader: str | None
    libraries: tuple[str, ...]
    nvram_shim: str | None
    argv: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    stdin: str | None
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    isolation_backend: str
    adapter_path: str | None
    network_policy: str
    timeout_seconds: int


@dataclasses.dataclass(frozen=True, slots=True)
class ProbeTermination:
    executed: bool
    reason: str
    exit_code: int | None
    signal: int | None
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    adapter_exit_code: int | None = None
    adapter_signal: int | None = None
    status_source: str = 'direct-process'


def _probe_path(value):
    q._relative(value)
    q._text(value, 'probe path')
    parts = value.split('/')
    _require(len(parts) <= 32 and all(len(p.encode('utf-8')) <= 255 for p in parts), 'Unbounded probe path')
    return value


def _host_path(value):
    _require(isinstance(value, str) and value.startswith('/') and str(pathlib.PurePosixPath(value)) == value,
        'Host program requires an explicit canonical absolute path')
    _probe_path(value[1:])


def _probe_parse(raw):
    value = json.loads(raw, object_pairs_hook=q._pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(AcquisitionError('Non-finite probe JSON')))
    q._object(value, ProbeSpec)
    _require(type(value['schema_version']) is int and value['schema_version'] == 1, 'Invalid probe schema')
    image = value['image_id']
    _require(isinstance(image, str) and bool(image.strip()) and '\x00' not in image and
        len(image.encode('utf-8')) <= 4096, 'Invalid probe image identity')
    for key in ('dive_generation','question_id','packet_sha256','contract_sha256'):
        q._digest(value[key])
    q._enum(value['method'], ('emulate',))
    q._enum(value['network_policy'], ('none',))
    q._enum(value['isolation_backend'], ('bwrap','sandbox-exec'))
    _require(type(value['timeout_seconds']) is int and 1 <= value['timeout_seconds'] <= 300, 'Invalid probe timeout')
    _probe_path(value['executable'])
    for key in ('loader','nvram_shim','stdin'):
        if value[key] is not None:
            _probe_path(value[key])
    for key in ('runner','adapter_path'):
        if value[key] is not None:
            _host_path(value[key])
    for key in ('inputs','libraries','outputs'):
        paths = value[key]
        _require(isinstance(paths, list) and len(paths) <= 256, 'Invalid probe path list')
        for path in paths:
            _probe_path(path)
        _require(paths == sorted(set(paths)), 'Probe paths require sorted unique entries')
        if key == 'outputs':
            _require(not any(other.startswith(path + '/') for path in paths for other in paths),
                'Output file/directory collision')
        value[key] = tuple(paths)
    argv = value['argv']
    _require(isinstance(argv, list) and 1 <= len(argv) <= 128, 'Invalid probe argv')
    for arg in argv:
        _require(isinstance(arg, str) and '\x00' not in arg and len(arg.encode('utf-8')) <= 4096, 'Invalid probe argument')
    _require(argv[0] == value['executable'], 'argv[0] must name the declared executable')
    environment = value['environment']
    _require(isinstance(environment, dict) and len(environment) <= 64, 'Invalid probe environment')
    for name, text in environment.items():
        _require(re.fullmatch('[A-Z_][A-Z0-9_]*', name) and name not in ('PATH','ENV','BASH_ENV','PYTHONPATH','PYTHONHOME','LIBPATH','SHLIB_PATH','GCONV_PATH','GLIBC_TUNABLES')
            and not name.startswith(('LD_','DYLD_','LDR_')), 'Unsafe probe environment name')
        _require(isinstance(text, str) and '\x00' not in text and len(text.encode('utf-8')) <= 4096, 'Invalid environment value')
    value['environment'] = tuple(sorted(environment.items()))
    value['argv'] = tuple(argv)
    return ProbeSpec(**value)


def load_probe_spec(path) -> ProbeSpec:
    """Load the strict bounded probe wire without following filesystem links."""
    try:
        return _probe_parse(_source(path, MAX_SPEC_BYTES)[0])
    except (OSError, ValueError, TypeError, KeyError, RecursionError,
            dive.FirmwareDiveError, q.FirmwareDiveQuestionError) as exc:
        raise AcquisitionError('Cannot load probe specification') from exc


def _probe_inputs(path, root, adapter=None):
    raw, identity = _source(path, MAX_SPEC_BYTES)
    spec = _probe_parse(raw)
    paths = [('executable',spec.executable), *[('library',p) for p in spec.libraries],
        *[('input',p) for p in spec.inputs]]
    paths.extend((role,p) for role,p in (('loader',spec.loader),('nvram-shim',spec.nvram_shim),
        ('stdin',spec.stdin)) if p is not None)
    if spec.runner is not None:
        paths.append(('runner',spec.runner))
    if adapter is not None:
        paths.append(('adapter',str(adapter.path)))
        if isinstance(adapter,_IsolationAdapter) and _needs_environment_launcher(spec):
            paths.append(('environment-launcher','/usr/bin/env'))
    dependencies, total, cached = [], 0, {}
    for role, relative in paths:
        target = pathlib.Path(relative) if role in ('runner','adapter','environment-launcher') else root / relative
        if role == 'environment-launcher':
            content, signature = _environment_launcher()
        elif role == 'adapter':
            content, signature = _source(target, MAX_DEPENDENCY_BYTES)
            if isinstance(adapter,_IsolationAdapter) and adapter.verified_identity is not None:
                _require((content,signature) == adapter.verified_identity, 'Adapter changed after readiness')
        elif target in cached:
            content, signature = cached[target]
        else:
            _require(len(cached) < 256, 'Too many staged probe files')
            content, signature = _source(target, MAX_DEPENDENCY_BYTES - total)
            total += len(content)
            cached[target] = (content,signature)
        dependencies.append((role, relative, signature, content))
    return spec, raw, identity, tuple(dependencies)


def _probe_ownership(con, run, root, spec):
    graph = firmware_chain.verified_retained_graph_snapshot(con, run, root,
        image_id=spec.image_id, dive_generation=spec.dive_generation)
    rows = dive._rows(con, spec.image_id)
    dive._history(run, rows, graph)
    owners = [row for row in rows['runs'] if row['dive_generation'] == spec.dive_generation]
    assignments = [row for row in rows['questions'] if
        (row['dive_generation'],row['question_id']) == (spec.dive_generation,spec.question_id)]
    _require(len(owners) == len(assignments) == 1, 'Probe requires exactly one prepared question')
    row, = assignments
    raw = dive._read(run, row['packet_path'], row['packet_sha256'], q.MAX_PACKET_BYTES)
    packet = dive._json(raw)
    contract = packet['acquisition_contract']
    _require(row['packet_sha256'] == spec.packet_sha256 and q._hash(contract) == spec.contract_sha256,
        'Probe packet or contract differs')
    question = dive._question(packet['question'])
    expected = json.loads(q.packet_bytes(question, graph))['acquisition_contract']
    _require(contract == expected and contract['image_id'] == spec.image_id and
        contract['question_id'] == spec.question_id and contract['method'] == spec.method == 'emulate' and
        contract['artifact_kinds'] == ['probe-manifest'] and
        contract['acquisition_class'] == 'no-network-isolated-probe' and contract['network'] == 'none' and
        contract['max_timeout_seconds'] == 300 and contract['max_stdout_bytes'] == MAX_PROBE_STREAM_BYTES and
        contract['max_stderr_bytes'] == MAX_PROBE_STREAM_BYTES and contract['max_output_bytes'] == MAX_PROBE_OUTPUT_BYTES and
        contract['max_files'] == 256, 'Probe exceeds exact question acquisition authority')
    dive._extracts(run, question.extract_records)
    return graph, rows, raw


@dataclasses.dataclass(frozen=True, slots=True)
class _IsolationAdapter:
    backend: str
    path: pathlib.Path
    verified_identity: tuple | None = None

    def command(self, spec, staging, output):
        if self.backend == 'bwrap':
            guest = {spec.executable, *spec.libraries, *spec.inputs}
            guest.update(p for p in (spec.loader,spec.nvram_shim,spec.stdin) if p is not None)
            _require(not any(p.split('/')[0] in ('proc','dev','output','runner') for p in guest),
                'Probe path collides with reserved isolation mount')
            argv = [str(self.path), '--unshare-all', '--die-with-parent', '--new-session',
                '--unshare-user','--disable-userns','--clearenv','--cap-drop','ALL']
            for directory in dive._tree_directories(dict.fromkeys(guest)):
                if directory:
                    argv += ['--dir','/'+directory]
            for name in sorted(guest):
                argv += ['--ro-bind',str(staging/name),'/'+name]
            if spec.runner:
                argv += ['--ro-bind',str(staging / '_runner'),'/runner']
            argv += ['--ro-bind',str(output),'/output','--proc','/proc','--dev','/dev',
                '--remount-ro','/','--remount-ro','/dev','--remount-ro','/proc']
            for name in spec.outputs:
                argv += ['--bind',str(output/name),'/output/'+name]
            argv += ['--chdir','/output']
            for name,value in spec.environment:
                argv += ['--setenv',name,value]
            if spec.nvram_shim:
                argv += ['--setenv','LD_PRELOAD','/'+spec.nvram_shim]
            command = (['/runner'] if spec.runner else []) + (['/'+spec.loader] if spec.loader else [])
            if spec.loader and spec.libraries:
                command += ['--library-path',':'.join(sorted({'/'+str(pathlib.PurePosixPath(p).parent)
                    for p in spec.libraries}))]
            return argv + ['--'] + command + ['/' + spec.executable, *spec.argv[1:]]
        profile = _sandbox_profile(staging, output, spec.outputs)
        command = ([str(staging / '_runner')] if spec.runner else []) + ([str(staging/spec.loader)] if spec.loader else [])
        firmware = [*command,str(staging/spec.executable),*spec.argv[1:]]
        if _needs_environment_launcher(spec):
            environment = [name+'='+value for name,value in spec.environment]
            if spec.nvram_shim:
                environment.append('DYLD_INSERT_LIBRARIES='+str(staging/spec.nvram_shim))
            firmware = [str(staging/'_environment-launcher'),'-i',*environment,*firmware]
        return [str(self.path), '-p',profile, *firmware]


def _sandbox_profile(staging, output, outputs=()):
    # SBPL strings are quoted with JSON; paths are generated private local paths.
    reads = [str(staging), '/System','/usr/lib','/private/var/db/dyld','/dev/null','/dev/urandom']
    return '(version 1)(deny default)(deny network*)(deny process-fork)(allow process-exec)(allow sysctl-read)(allow file-read* ' + \
        ' '.join('(subpath '+json.dumps(path)+')' for path in reads) + \
        ')' + ''.join('(allow file-write* (literal '+json.dumps(str(output/name))+'))' for name in outputs)


def _select_adapter(spec):
    candidates = [spec.adapter_path] if spec.adapter_path else (
        ['/usr/bin/bwrap','/bin/bwrap'] if spec.isolation_backend == 'bwrap' else ['/usr/bin/sandbox-exec'])
    compatible = sys.platform.startswith('linux') if spec.isolation_backend == 'bwrap' else sys.platform == 'darwin'
    if not compatible:
        return None
    for candidate in candidates:
        path = pathlib.Path(candidate)
        if path.name != spec.isolation_backend:
            continue
        try:
            before = _source(path, MAX_DEPENDENCY_BYTES)
            _require(os.access(path, os.X_OK), 'Adapter is not executable')
            return _IsolationAdapter(spec.isolation_backend, path, before)
        except (OSError, AcquisitionError, dive.FirmwareDiveError):
            continue
    return None


def _adapter_ready(adapter):
    """Check a private ordinary-permission copy, never the mutable host path."""
    python = pathlib.Path(sys.executable).resolve()
    if adapter.backend == 'bwrap':
        net = os.stat('/proc/self/ns/net').st_ino
        script = 'import os; raise SystemExit(os.stat("/proc/self/ns/net").st_ino == '+str(net)+')'
        command = [str(adapter.path),'--unshare-all','--die-with-parent','--new-session',
            '--unshare-user','--disable-userns','--clearenv','--cap-drop','ALL',
            '--ro-bind','/','/','--proc','/proc','--dev','/dev',
            '--remount-ro','/','--remount-ro','/dev','--remount-ro','/proc',
            '--',str(python),'-I','-S','-c',script]
    else:
        script = 'import socket\ntry: socket.socket()\nexcept PermissionError: raise SystemExit(0)\nraise SystemExit(1)'
        command = [str(adapter.path),'-p','(version 1)(allow default)(deny network*)',str(python),'-I','-S','-c',script]
    termination, _, _ = _process(command, {}, None, 3, pathlib.Path('/'))
    return termination == ProbeTermination(True,'exited',0,None,False,False,False)


def _kill_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        # Darwin returns EPERM for groups containing only unreaped zombies.
        # Reaping the dead leader distinguishes this from a live kill failure.
        if process.poll() is None:
            raise


def _child_limits():
    limits = [('RLIMIT_FSIZE',MAX_PROBE_OUTPUT_BYTES),
              ('RLIMIT_NPROC',MAX_PROBE_PROCESSES),('RLIMIT_NOFILE',64)]
    if sys.platform.startswith('linux'):
        limits.insert(0, ('RLIMIT_AS',MAX_PROBE_ADDRESS_BYTES))
    for name, maximum in limits:
        resource.setrlimit(getattr(resource,name),(maximum,maximum))


def _limits_available():
    if resource is None or os.getuid() == 0 or not (sys.platform.startswith('linux') or sys.platform == 'darwin'):
        return False
    for name, maximum in (('RLIMIT_FSIZE',MAX_PROBE_OUTPUT_BYTES),
            ('RLIMIT_NPROC',MAX_PROBE_PROCESSES),('RLIMIT_NOFILE',64)):
        key = getattr(resource,name,None)
        if key is None:
            return False
        try:
            _, hard = resource.getrlimit(key)
        except (OSError,ValueError):
            return False
        if hard != resource.RLIM_INFINITY and hard < maximum:
            return False
    return True


def _memory_limits_available():
    """Only Linux RLIMIT_AS is enforceable here; other hosts fail closed."""
    if resource is None or not sys.platform.startswith('linux'):
        return False
    key = getattr(resource, 'RLIMIT_AS', None)
    if key is None:
        return False
    try:
        _, hard = resource.getrlimit(key)
    except (OSError, ValueError):
        return False
    return hard == resource.RLIM_INFINITY or hard >= MAX_PROBE_ADDRESS_BYTES


def _prepare_outputs(output, declared):
    with contextlib.ExitStack() as stack:
        parent = dive._directory(output,stack)
        owners = dive._tree_owners(parent,dive._tree_directories(dict.fromkeys(declared)),stack,create=True)
        for name in declared:
            path = pathlib.PurePosixPath(name)
            owner = owners[str(path.parent) if str(path.parent) != '.' else '']
            fd = os.open(path.name,os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,0o600,dir_fd=owner)
            os.close(fd)
        for owner in reversed(tuple(owners.values())):
            os.fchmod(owner,0o500)


def _output_guard(output, declared, stack):
    """Retain bounded directory owners and reject size, shape or inode drift."""
    parent = dive._directory(output,stack)
    directories = dive._tree_directories(dict.fromkeys(declared))
    owners = dive._tree_owners(parent,directories,stack)
    expected = {directory:{pathlib.PurePosixPath(name).name for name in [*declared,*directories] if name and
        (str(pathlib.PurePosixPath(name).parent) if str(pathlib.PurePosixPath(name).parent) != '.' else '') == directory}
        for directory in directories}
    identities = {}
    for name in declared:
        path = pathlib.PurePosixPath(name)
        owner = owners[str(path.parent) if str(path.parent) != '.' else '']
        info = os.stat(path.name,dir_fd=owner,follow_symlinks=False)
        identities[name] = (info.st_dev,info.st_ino)
    def valid():
        total = 0
        try:
            for name,owner in owners.items():
                if os.fstat(owner).st_mode & 0o222 or dive._directory_names(owner,len(expected[name])) != expected[name]:
                    return False
                if name:
                    path = pathlib.PurePosixPath(name)
                    ancestor = owners[str(path.parent) if str(path.parent) != '.' else '']
                    info = os.stat(path.name,dir_fd=ancestor,follow_symlinks=False)
                    actual = os.fstat(owner)
                    if not stat.S_ISDIR(info.st_mode) or (info.st_dev,info.st_ino) != (actual.st_dev,actual.st_ino):
                        return False
            for name,identity in identities.items():
                path = pathlib.PurePosixPath(name)
                owner = owners[str(path.parent) if str(path.parent) != '.' else '']
                info = os.stat(path.name,dir_fd=owner,follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or (info.st_dev,info.st_ino) != identity:
                    return False
                total += info.st_size
                if total > MAX_PROBE_OUTPUT_BYTES:
                    return False
            return True
        except (OSError,dive.FirmwareDiveError):
            return False
    _require(valid(), 'Invalid initial output tree')
    return valid


def _process(command, environment, stdin, timeout, cwd, *, output_paths=None):
    """Drain both pipes while retaining fixed prefixes; always kill/reap the group."""
    process = None
    streams = [bytearray(), bytearray()]
    truncated = [False, False]
    timed_out = False
    output_limit = False
    killed = False
    def kill():
        nonlocal killed
        if not killed:
            _kill_group(process)
            killed = True
    try:
        if not _limits_available():
            return ProbeTermination(False,'unsupported-limits',None,None,False,False,False), b'', b''
        with contextlib.ExitStack() as stack:
            guard = _output_guard(cwd,output_paths,stack) if output_paths is not None else None
            source = subprocess.DEVNULL
            if stdin:
                path = pathlib.Path(stdin)
                parent = dive._directory(path.parent,stack)
                _, identity = dive._read_regular(parent,path.name,MAX_DEPENDENCY_BYTES)
                fd = os.open(path.name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=parent)
                source = stack.enter_context(os.fdopen(fd,'rb'))
                _require(dive._file_identity(os.fstat(source.fileno())) == identity, 'Probe stdin changed')
            try:
                process = subprocess.Popen(command, shell=False, start_new_session=True, close_fds=True,
                    stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, cwd=cwd,
                    preexec_fn=_child_limits)
            except subprocess.SubprocessError:
                return ProbeTermination(False,'unsupported-limits',None,None,False,False,False), b'', b''
            selector = stack.enter_context(selectors.DefaultSelector())
            for index, stream in enumerate((process.stdout,process.stderr)):
                stack.callback(stream.close)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            deadline = time.monotonic() + timeout
            while selector.get_map() or process.poll() is None:
                if not output_limit and guard is not None and not guard():
                    output_limit = True
                    kill()
                    deadline = time.monotonic() + 1
                if not timed_out and not output_limit and time.monotonic() >= deadline:
                    timed_out = True
                    kill()
                    deadline = time.monotonic() + 1
                elif (timed_out or output_limit) and time.monotonic() >= deadline:
                    raise AcquisitionError('Probe pipes did not close after termination')
                for key, _ in selector.select(min(0.05, max(0,deadline-time.monotonic()))):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        index = key.data
                        available = MAX_PROBE_STREAM_BYTES-len(streams[index])
                        streams[index].extend(chunk[:available])
                        truncated[index] |= len(chunk) > available
            code = process.wait(timeout=1)
            kill()
            output_limit |= guard is not None and not guard()
            reason = 'output-limit' if output_limit or code == -signal.SIGXFSZ else 'timeout' if timed_out else 'signal' if code < 0 else 'exited'
            return ProbeTermination(True,reason,code if code >= 0 else None,-code if code < 0 else None,
                timed_out,*truncated), bytes(streams[0]), bytes(streams[1])
    except OSError:
        if process is None:
            return ProbeTermination(False,'tool-unavailable',None,None,False,False,False), b'', b''
        raise
    finally:
        if process is not None:
            try:
                kill()
            except OSError as exc:
                try:
                    process.kill()
                finally:
                    process.wait(timeout=1)
                raise AcquisitionError('Cannot clean up probe process group') from exc
            finally:
                process.wait(timeout=1)


def _stage_probe(staging, dependencies):
    contents = {relative:raw for role,relative,_,raw in dependencies if role not in ('runner','adapter','environment-launcher')}
    runners = [raw for role,_,_,raw in dependencies if role == 'runner']
    _require('_runner' not in contents or not runners, 'Reserved staging path collision')
    if runners:
        contents['_runner'] = runners[0]
    helpers = [raw for role,_,_,raw in dependencies if role == 'environment-launcher' and raw is not None]
    if helpers:
        _require('_environment-launcher' not in contents, 'Reserved environment launcher path collision')
        contents['_environment-launcher'] = helpers[0]
    _stage_contents(staging,contents)
    return contents


def _stage_contents(staging, contents):
    with contextlib.ExitStack() as stack:
        parent = dive._directory(staging, stack)
        owners = dive._tree_owners(parent, dive._tree_directories(contents), stack, create=True)
        for relative, raw in contents.items():
            path = pathlib.PurePosixPath(relative)
            owner = owners[str(path.parent) if str(path.parent) != '.' else '']
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500, dir_fd=owner)
            with os.fdopen(fd,'wb') as stream:
                stream.write(raw)


def _output_snapshot(output, declared):
    with contextlib.ExitStack() as stack:
        parent = dive._directory(output,stack)
        owners = dive._tree_owners(parent,dive._tree_directories(dict.fromkeys(declared)),stack)
        return {name:dive._file_identity(os.stat(pathlib.PurePosixPath(name).name,
            dir_fd=owners[str(pathlib.PurePosixPath(name).parent) if str(pathlib.PurePosixPath(name).parent) != '.' else ''],
            follow_symlinks=False)) for name in declared}


def _output_files(output, declared, before):
    result, total, entries = {}, 0, {}
    directories = dive._tree_directories(dict.fromkeys(declared))
    with contextlib.ExitStack() as stack:
        parent = dive._directory(output, stack)
        owners = dive._tree_owners(parent, directories, stack)
        for relative, owner in owners.items():
            expected = {pathlib.PurePosixPath(name).name for name in [*declared,*directories] if name and
                (str(pathlib.PurePosixPath(name).parent) if str(pathlib.PurePosixPath(name).parent) != '.' else '') == relative}
            entries[relative] = dive._directory_names(owner,len(expected))
            _require(entries[relative] == expected, 'Probe output tree changed')
        for name in declared:
            path = pathlib.PurePosixPath(name)
            relative = str(path.parent) if str(path.parent) != '.' else ''
            owner = owners[relative]
            raw, identity = dive._read_regular(owner,path.name,MAX_PROBE_OUTPUT_BYTES-total)
            if identity == before[name]:
                continue
            total += len(raw)
            result['outputs/'+name] = raw
    return result


def _static_runner(raw):
    """Accept bounded ELF program headers only, with no dynamic interpreter."""
    if len(raw) < 52 or raw[:4] != b'\x7fELF' or raw[4] not in (1,2) or raw[5] not in (1,2):
        return False
    wide, endian = raw[4] == 2, '<' if raw[5] == 1 else '>'
    if wide and len(raw) < 64:
        return False
    offset = struct.unpack_from(endian+('Q' if wide else 'I'),raw,32 if wide else 28)[0]
    size, count = struct.unpack_from(endian+'HH',raw,54 if wide else 42)
    if size < (56 if wide else 32) or count > 4096 or offset + size*count > len(raw):
        return False
    return all(struct.unpack_from(endian+'I',raw,offset+i*size)[0] != 3 for i in range(count))


def _needs_environment_launcher(spec):
    return spec.isolation_backend == 'sandbox-exec' and bool(spec.environment or spec.nvram_shim)


def _environment_launcher():
    try:
        raw, identity = _source('/usr/bin/env',MAX_DEPENDENCY_BYTES)
        return (raw,identity) if identity[2] & 0o111 else (None,None)
    except (OSError,dive.FirmwareDiveError):
        return None,None


def _compatible_environment_launcher(raw):
    if raw is None or len(raw) < 8:
        return False
    native = {'x86_64':0x1000007,'arm64':0x100000c,'aarch64':0x100000c}.get(platform.machine())
    thin = {b'\xcf\xfa\xed\xfe':'<',b'\xfe\xed\xfa\xcf':'>',b'\xce\xfa\xed\xfe':'<',b'\xfe\xed\xfa\xce':'>'}
    fat = {b'\xca\xfe\xba\xbe':('>',20),b'\xbe\xba\xfe\xca':('<',20),
        b'\xca\xfe\xba\xbf':('>',32),b'\xbf\xba\xfe\xca':('<',32)}
    if raw[:4] in thin:
        endian = thin[raw[:4]]
        return len(raw) >= 32 and struct.unpack_from(endian+'I',raw,4)[0] == native
    if raw[:4] not in fat:
        return False
    endian, width = fat[raw[:4]]
    count = struct.unpack_from(endian+'I',raw,4)[0]
    return 1 <= count <= 32 and len(raw) >= 8+width*count and any(
        struct.unpack_from(endian+'I',raw,8+width*i)[0] == native for i in range(count))


def _adapter_termination(termination, backend):
    """Native tool wait status does not authenticate the payload wait status."""
    return dataclasses.replace(termination,
        reason={'exited':'adapter-exited','signal':'adapter-signal'}.get(termination.reason,termination.reason),
        exit_code=None,signal=None,adapter_exit_code=termination.exit_code,
        adapter_signal=termination.signal,status_source=backend+'-adapter')


def _execute_probe(spec, dependencies, adapter):
    if adapter is None:
        return ProbeTermination(False,'isolation-unavailable',None,None,False,False,False), b'', b'', {}
    if not _limits_available() or not _memory_limits_available():
        return ProbeTermination(False,'unsupported-limits',None,None,False,False,False), b'', b'', {}
    helper = next(((raw,identity) for role,_,identity,raw in dependencies if role == 'environment-launcher'),None)
    if isinstance(adapter,_IsolationAdapter) and _needs_environment_launcher(spec) and (
            helper is None or not _compatible_environment_launcher(helper[0])):
        return ProbeTermination(False,'unsupported-helper',None,None,False,False,False), b'', b'', {}
    if isinstance(adapter,_IsolationAdapter) and adapter.backend == 'bwrap' and spec.runner:
        raw = next(raw for role,_,_,raw in dependencies if role == 'runner')
        if not _static_runner(raw):
            return ProbeTermination(False,'unsupported-runner',None,None,False,False,False), b'', b'', {}
    with tempfile.TemporaryDirectory(prefix='cba-probe-',dir=pathlib.Path(tempfile.gettempdir()).resolve()) as directory:
        base = pathlib.Path(directory)
        staging, output = base/'firmware', base/'output'
        staging.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        staged = _stage_probe(staging, dependencies)
        _prepare_outputs(output,spec.outputs)
        executing = adapter
        tool_contents = None
        if isinstance(adapter,_IsolationAdapter):
            tool = base/'tool'
            tool.mkdir(mode=0o700)
            raw = next(raw for role,_,_,raw in dependencies if role == 'adapter')
            tool_contents = {adapter.path.name:raw}
            _stage_contents(tool,tool_contents)
            executing = dataclasses.replace(adapter,path=tool/adapter.path.name,verified_identity=None)
            try:
                ready = _adapter_ready(executing)
            except OSError:
                ready = False
            dive._checked_install(tool,tool_contents,base)
        else:
            ready = True
        # Only the isolated guest receives declared environment and shim values.
        # Host adapter startup always uses a fixed, loader-variable-free mapping.
        dive._checked_install(staging,staged,base)
        if helper is not None and _environment_launcher() != helper:
            return ProbeTermination(False,'unsupported-helper',None,None,False,False,False), b'', b'', {}
        stdin = staging/spec.stdin if spec.stdin else None
        output_before = _output_snapshot(output,spec.outputs)
        if ready:
            termination, stdout, stderr = _process(executing.command(spec,staging,output),{},stdin,
                spec.timeout_seconds,output,output_paths=spec.outputs)
        else:
            termination, stdout, stderr = ProbeTermination(False,'isolation-unavailable',None,None,False,False,False), b'', b''
        if isinstance(adapter,_IsolationAdapter):
            termination = _adapter_termination(termination,adapter.backend)
        if tool_contents is not None:
            dive._checked_install(tool,tool_contents,base)
        dive._checked_install(staging, staged, base)
        return termination, stdout, stderr, (_output_files(output,spec.outputs,output_before)
            if termination.executed and termination.reason != 'output-limit' and
                (termination.status_source == 'direct-process' or
                 termination.reason == 'adapter-exited' and termination.adapter_exit_code == 0) else {})


def _sealed_probe_limits(backend):
    return dict(stdout_bytes=MAX_PROBE_STREAM_BYTES,
        stderr_bytes=MAX_PROBE_STREAM_BYTES, output_bytes=MAX_PROBE_OUTPUT_BYTES,
        output_files=256, address_space_bytes=MAX_PROBE_ADDRESS_BYTES,
        process_limit=MAX_PROBE_PROCESSES, descriptor_limit=64,
        file_size_limit=MAX_PROBE_OUTPUT_BYTES,
        output_policy='precreated-exact-files',
        user_namespace_policy=('isolated-nested-disabled'
            if backend == 'bwrap' else 'not-applicable'))


def _probe_build(run, inputs, termination, stdout, stderr, outputs, after_inputs):
    spec, _, _, dependencies = inputs
    sealed = dataclasses.asdict(spec)
    sealed['environment'] = dict(spec.environment)
    sealed.pop('adapter_path')
    sealed['runner'] = None if spec.runner is None else 'verified-runner'
    sealed.update(_sealed_probe_limits(spec.isolation_backend))
    records = []
    after_sources = {(role,path):raw for role,path,_,raw in after_inputs[3]}
    for role,path,_,raw in dependencies:
        fact = None if raw is None else dict(sha256=dive._digest(raw),byte_count=len(raw))
        after_raw = after_sources[(role,path)]
        after_fact = None if after_raw is None else dict(sha256=dive._digest(after_raw),byte_count=len(after_raw))
        records.append(dict(role=role,path=None if role in ('runner','adapter','environment-launcher') else path,
            before=fact,after=after_fact))
    contents = dict(outputs) | {'evidence/stdout':stdout, 'evidence/stderr':stderr}
    evidence = [dict(path=path,sha256=dive._digest(raw),byte_count=len(raw)) for path,raw in sorted(contents.items())]
    body = dict(kind='probe',spec=sealed,network_policy='none',dependencies=records,
        termination=dataclasses.asdict(termination),evidence=evidence,
        runtime=dict(platform=sys.platform,version=platform.release(),
            stream_source=termination.status_source if termination.executed else 'not-executed',
            tool_runtime_limitation='Staged adapter host runtime before isolation is trusted tooling',
            system_read_roots=['/System','/usr/lib','/private/var/db/dyld','/dev/null','/dev/urandom']
                if spec.isolation_backend == 'sandbox-exec' else [],
            limitation='Apple system runtime reads are not firmware library evidence'
                if spec.isolation_backend == 'sandbox-exec' else None))
    identity = q._hash(body)
    manifest = body | dict(acquisition_id=identity)
    contents.update({'spec.json':q._bytes(sealed),'manifest.json':q._bytes(manifest)})
    relative = 'artifacts/firmware-dive-probes/' + identity
    total = sum(row['byte_count'] for row in evidence)
    summary = AcquisitionSummary(spec.image_id,spec.dive_generation,spec.question_id,identity,'probe',
        str(run/relative/'spec.json'),str(run/relative/'manifest.json'),len(evidence),total)
    record = dict(image_id=spec.image_id,dive_generation=spec.dive_generation,question_id=spec.question_id,
        acquisition_id=identity,kind='probe',contract_sha256=spec.contract_sha256,
        spec_path=relative+'/spec.json',spec_sha256=dive._digest(contents['spec.json']),
        manifest_path=relative+'/manifest.json',manifest_sha256=dive._digest(contents['manifest.json']),
        evidence_paths=q._bytes(sorted([relative+'/'+row['path'] for row in evidence],key=q._bytes)).decode(),
        details=q._bytes(dict(kind='probe',byte_count=total,file_count=len(evidence))).decode())
    return summary, contents, record


def run_probe(con, run_dir, root, spec_path) -> AcquisitionSummary:
    """Run one exact prepared question through isolation; atomically seal facts."""
    started = False
    try:
        _require(not con.in_transaction, 'Probe requires no active transaction')
        run, path, root = dive._selector(run_dir), dive._selector(spec_path), dive._selector(root)
        baseline = _probe_inputs(path,root)
        spec = baseline[0]
        # Verify ownership before even executing the fixed adapter readiness test.
        con.execute('BEGIN')
        started = True
        ownership = _probe_ownership(con,run,root,spec)
        con.rollback()
        started = False
        adapter = _select_adapter(spec)
        inputs = _probe_inputs(path,root,adapter)
        _require(inputs[:3] == baseline[:3] and tuple(d for d in inputs[3] if d[0] not in ('adapter','environment-launcher')) == baseline[3],
            'Probe specification or inputs changed before execution')
        termination, stdout, stderr, outputs = _execute_probe(spec,inputs[3],adapter)
        after_inputs = _probe_inputs(path,root,adapter)
        if not termination.executed and termination.reason == 'unsupported-helper':
            _require(after_inputs[:3] == inputs[:3] and
                tuple(d for d in after_inputs[3] if d[0] != 'environment-launcher') ==
                tuple(d for d in inputs[3] if d[0] != 'environment-launcher'),
                'Non-helper dependencies changed during refused probe')
        else:
            _require(after_inputs == inputs, 'Probe dependencies changed during execution')
        summary, contents, record = _probe_build(run,inputs,termination,stdout,stderr,outputs,after_inputs)
        destination = pathlib.Path(summary.manifest_path).parent
        dive._install(destination,contents,run)
        con.execute('BEGIN IMMEDIATE')
        started = True
        _require(_probe_inputs(path,root,adapter) == after_inputs and
            _probe_ownership(con,run,root,spec) == ownership, 'Probe dependencies changed before publication')
        dive._checked_install(destination,contents,run)
        prior = surface._query(con,'SELECT * FROM cba_firmware_dive_acquisitions WHERE acquisition_id=?',
            (summary.acquisition_id,))
        if prior:
            _require(len(prior) == 1 and all(prior[0][key] == value for key,value in record.items()),
                'Existing probe ownership differs')
        else:
            db.put(con,'cba_firmware_dive_acquisitions',record,commit=False)
        con.commit()
        started = False
        return summary
    except Exception as exc:
        if started:
            con.rollback()
        if isinstance(exc,(sqlite3.Error,db.DbError)):
            raise AcquisitionError('database operation failed') from exc
        if isinstance(exc,(OSError,ValueError,TypeError,KeyError,RecursionError,dive.FirmwareDiveError,
                q.FirmwareDiveQuestionError,firmware_chain.FirmwareChainError,
                firmware_fpcheck.FpcheckError,surface.SurfaceError,subprocess.SubprocessError)):
            raise AcquisitionError('Cannot run isolated probe') from exc
        raise
