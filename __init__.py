#!/usr/bin/env python3

from __future__ import print_function
import subprocess
import tempfile
import json
import os

import sibyl.testlauncher
import sibyl.abi
import sibyl.abi.arm
import sibyl.abi.x86
import sibyl.abi.mips
import sibyl.config
from binaryninja import BackgroundTaskThread, LabelField, ChoiceField, TextLineField
from binaryninja import log_info, log_debug, log_error, get_form_input, PluginCommand, Settings
import functools


# Map calling convention [Binja arch][Binja cc name] -> sibyl cc
CC_MAP = {
    'armv7': {
        'cdecl': 'ABI_ARM',
    },
    'armv7eb': {
        'cdecl': 'ABI_ARM',
    },
    'mips32': {
        'o32': 'ABI_MIPS_O32',
    },
    'mipsel32': {
        'o32': 'ABI_MIPS_O32',
    },
    'thumb2': {
        'cdecl': 'ABI_ARM',
    },
    'thumb2eb': {
        'cdecl': 'ABI_ARM',
    },
    'x86': {
        'cdecl': 'ABIStdCall_x86_32',
        'fastcall': 'ABIFastCall_x86_32',
        'stdcall': 'ABIStdCall_x86_32',
    },
    'x86_64': {
        'sysv': 'ABI_AMD64_SYSTEMV',
        'win64': 'ABI_AMD64_MS',
    },
}

# Arch mapping [Binja arch] -> Miasm arch
ARCH_MAP = {
    'aarch64': 'aarch64l',  # TODO: Why doesn't binja have aarch64b and aarch64l?
    'armv7': 'arml',
    'armv7eb': 'armb',
    'thumb2': 'armtl',
    'thumb2eb': 'armtb',
    'mipsel32': 'mips32l',
    'mips32': 'mips32b',
    'x86': 'x86_32',
    'x86_64': 'x86_64',
}
ARCHS = list(ARCH_MAP.values())

SIBYL_CMD = 'sibyl'
TIMEOUT_CMD = 'timeout'

settings = Settings()
settings.register_group('binja_sibyl', 'Sibyl')
if not settings.contains('binja_sibyl.sibyl_command_path'):
    settings.register_setting('binja_sibyl.sibyl_command_path',
                              '{"description": "Sibyl Command Path",'
                              ' "title": "Sibyl Command Path",'
                              f' "default": "{SIBYL_CMD}",'
                              ' "type": "string"}')
if not settings.contains('binja_sibyl.timeout_command_path'):
    settings.register_setting('binja_sibyl.timeout_command_path',
                              '{"description": "Timeout Command Path",'
                              ' "title": "Timeout Command Path",'
                              f' "default": "{TIMEOUT_CMD}",'
                              ' "type": "string"}')

CHUNK_SIZE = 8


def exec_cmd(cmd):
    logger = 'binja_sibyl.exec_cmd'
    log_debug(f'cmd="{cmd}"', logger=logger)
    out = None
    p = subprocess.run(cmd, shell=True, close_fds=True, capture_output=True)
    rc = p.returncode
    if rc == 0:
        out = p.stdout
    # else:
    #     log_error(f'failed: {p.stderr}', logger=logger)
    log_debug(f'out={out}', logger=logger)
    return out


def gen_temp_bin(content):
    h, temp = tempfile.mkstemp(suffix='.bin')
    os.close(h)

    with open(temp, 'wb') as f:
        f.write(content)

    return temp


def get_timeout_command():
    return Settings().get_string("binja_sibyl.timeout_command_path")


def get_sibyl_command():
    return Settings().get_string("binja_sibyl.sibyl_command_path")


def get_base_addr(addr):
    a = addr if addr % 0x1000 == 0 else 0
    o = a - addr
    return a, o


def analyze(tests, bin_file, base_addr, arch, addr, abi, engine, timeout=3, sibyl_timeout=2):
    logger = 'binja_sibyl.analyze'

    base_addr, ofs = get_base_addr(base_addr)
    _addr = addr
    if ofs != 0:
        log_debug(f'base address changed to {base_addr:#x} (offset={ofs:+#x})', logger=logger)
        addr = addr + ofs

    _cmd = f'{get_timeout_command()} {timeout+1} {get_sibyl_command()} find -o JSON'
    opts = f' -a {arch} -b {abi} -t {tests} -i {timeout} -m {base_addr} -j {engine}'
    cmd = f'{_cmd}{opts} {bin_file} {addr}'
    r = exec_cmd(cmd)

    out = None
    if r:
        try:
            d = json.loads(r)
            out = [(r['address'] - ofs, r['functions']) for r in d['results']]
        except Exception:
            log_error(f'failed to analyze {_addr}: {r}', logger=logger)

    return out


def analyze_multi(tests, bin_file, base_addr, arch, addrl, abi, engine, timeout=3,
                  sibyl_timeout=2):
    logger = 'binja_sibyl.analyze_multi'

    base_addr, ofs = get_base_addr(base_addr)
    _addrl = addrl
    if ofs != 0:
        log_debug(f'base address changed to {base_addr:#x} (offset={ofs:+#x})', logger=logger)
        addrl = list(map(lambda a: a + ofs, addrl))

    addrl_str = ' '.join([str(a) for a in addrl])
    _cmd = f'{get_timeout_command()} {timeout} {get_sibyl_command()} find -o JSON'
    opts = f' -a {arch} -b {abi} -t {tests} -i {sibyl_timeout} -m {base_addr} -j {engine}'
    cmd = f'{_cmd}{opts} {bin_file} {addrl_str}'
    r = exec_cmd(cmd)

    out = None
    if r:
        try:
            d = json.loads(r)
            out = [(r['address'] - ofs, r['functions']) for r in d['results']]
        except Exception:
            log_error(f'failed to analyze {" ".join([str(a) for a in _addrl])}: {r}',
                      logger=logger)

    return out


class AnalysisThread(BackgroundTaskThread):
    """
    Sibyl's IDA plugin uses subprocesses in order to fully exploit multiprocessing.
    That feels a bit hacky to me so I'm going with a simple background thread...
    This ways it's way slower though.
    """

    logger = 'binja_sibyl.AnalysisThread'

    def __init__(self, tests, content, base_addr, arch, funk_addrs, funk_ccs, callback,
                 timeout=3, sibyl_timeout=2,
                 multi=False):

        super(AnalysisThread, self).__init__('Running Sibyl...', True)

        self._tests = tests
        self._content = content
        self._arch = arch
        self._base_addr = base_addr
        self._funk_addrs = funk_addrs
        self._funk_ccs = funk_ccs
        self._callback = callback
        self._timeout = timeout
        self._sibyl_timeout = sibyl_timeout
        self._multi = multi

    def run(self):
        logger = self.logger + '.run'

        chunk_size = CHUNK_SIZE

        engine_name = sibyl.config.config.jit_engine

        log_info(f'arch={self._arch} engine={engine_name} base_addr={self._base_addr:#08x}',
                 logger=logger)

        nfunks = len(self._funk_addrs)
        nfunks_ = float(nfunks)

        if nfunks == 0:
            return

        log_info(f'running on {self._funk_addrs[0]:#x}...', logger=logger)

        bin_file = gen_temp_bin(self._content)

        log_info(f'bin_file={bin_file}', logger=logger)

        count = 0

        if self._multi:
            tbl = {}
            for addr, cc in zip(self._funk_addrs, self._funk_ccs):
                try:
                    chunkl = tbl[cc]
                    chunk = chunkl[-1]
                    if len(chunk) < chunk_size:
                        chunk.append(addr)
                    else:
                        chunkl.append([addr])
                except KeyError:
                    tbl[cc] = [[addr]]

            for cc, chunkl in tbl.items():
                for chunk in chunkl:
                    if self.cancelled:
                        break

                    c = len(chunk)
                    count += c
                    p = float(100 * count) / nfunks_
                    a = chunk[0]
                    self.progress = (f'Sibyl: analyzing {c} function(s) ({a:#x},...)'
                                     f' ({count}/{nfunks}={p:.2f}%)...')

                    rl = analyze_multi(self._tests, bin_file, self._base_addr, self._arch, chunk,
                                       cc, engine_name,
                                       timeout=self._timeout, sibyl_timeout=self._sibyl_timeout)
                    if rl:
                        for a, fl in rl:
                            if fl:
                                self._callback(a, fl)
        else:
            for addr, cc in zip(self._funk_addrs, self._funk_ccs):
                if self.cancelled:
                    break
                count += 1
                p = float(100 * count) / nfunks_
                self.progress = f'Sibyl: analyzing {addr:#x} ({count}/{nfunks}={p:.2f}%)...'
                rl = analyze(self._tests, bin_file, self._base_addr, self._arch,
                             addr, cc, engine_name,
                             timeout=self._timeout, sibyl_timeout=self._sibyl_timeout)
                if rl:
                    for a, fl in rl:
                        if fl:
                            self._callback(a, fl)

        self.progress = 'Sibyl: done.'
        self.finished = True

        log_info(f'analyzed {count} function(s): {self._funk_addrs[0]:#x}...', logger=logger)

        if os.path.exists(bin_file):
            os.unlink(bin_file)
            log_debug(f'{bin_file} removed', logger=logger)


def rename_function(bv, addr, names, prefix='', comment=True):
    logger = 'binja_sibyl.rename_function'
    names_str = ', '.join(names)
    log_info(f'{addr:#08x} -> [{names_str}]', logger=logger)
    funk = bv.get_function_at(addr)
    funk.name = prefix + names[0]
    if comment:
        funk.set_comment(addr, f'Sibyl: {names_str}')


def guess(bv, funks, tests_name,
          prefix='s_', add_comment=True, timeout=2, m_arch=None, multi=False):
    logger = 'binja_sibyl.guess'

    cc_map = CC_MAP[bv.arch.name]
    if m_arch is None:
        m_arch = ARCH_MAP[bv.arch.name]

    log_info(f'{bv.arch.name} -> {m_arch}', logger=logger)

    ntests = len(sibyl.config.config.available_tests[tests_name])

    funks = list(filter(lambda x: x.calling_convention.name in cc_map, funks))
    nfunks = len(funks)

    log_info(f'analyzing {nfunks} functions with {ntests} tests', logger=logger)

    if len(bv.sections) == 0:

        addrs = [f.start for f in funks]
        ccs = [cc_map[f.calling_convention.name] for f in funks]
        callback = functools.partial(rename_function, bv, prefix=prefix, comment=add_comment)

        bv_start = bv.start

        # Create and start the analysis thread
        analysis = AnalysisThread(
            tests_name,
            bv.read(bv_start, bv.length),
            bv_start,
            m_arch,
            addrs,
            ccs,
            callback,
            timeout=timeout + 1,
            sibyl_timeout=timeout,
            multi=multi,
        )
        analysis.start()

    else:
        func_tbl = {}
        for f in funks:
            a = f.start
            for k, s in bv.sections.items():
                if s.start <= a < s.end:
                    try:
                        func_tbl[k].append(f)
                    except KeyError:
                        func_tbl[k] = [f]
                    break

        for sn, funks in func_tbl.items():
            log_info(f'{sn}: {len(funks)} functions', logger=logger)
            sect = bv.sections[sn]
            sect_start = sect.start
            content = bv.read(sect_start, len(sect))
            # for f in funks:
            #     log_info(f'  {f}')
            addrs = [f.start for f in funks]
            ccs = [cc_map[f.calling_convention.name] for f in funks]
            callback = functools.partial(rename_function, bv, prefix=prefix, comment=add_comment)

            # Create and start the analysis thread
            analysis = AnalysisThread(
                tests_name,
                content,
                sect_start,
                m_arch,
                addrs,
                ccs,
                callback,
                timeout=timeout + 1,
                sibyl_timeout=timeout,
                multi=multi,
            )
            analysis.start()


def cmd_run(bv):
    logger = 'binja_sibyl.cmd_run'

    test_groups = list(sibyl.config.config.available_tests.keys())

    m_arch = ARCH_MAP[bv.arch.name]

    gui_label_options = LabelField('Options:')
    gui_tests = ChoiceField('Tests:', test_groups)
    gui_prefix = TextLineField('Function prefix:')
    gui_selector = ChoiceField('Function selector:', ('sub_.*', '.*'))
    gui_comment = ChoiceField('Add comment:', ('Yes', 'No'))
    gui_arch = ChoiceField('Architecture:', ARCHS, default=ARCHS.index(m_arch))

    ret = get_form_input(
        (gui_label_options, gui_tests, gui_prefix, gui_selector, gui_comment, gui_arch),
        'Sibyl'
    )

    # User canceled
    if not ret:
        return

    # Sanitize options
    tests_name = test_groups[gui_tests.result]
    rename_only_unknowns = gui_selector.choices[gui_selector.result] == 'sub_.*'
    add_comment = gui_comment.choices[gui_comment.result] == 'Yes'
    prefix = gui_prefix.result.strip()
    m_arch = gui_arch.choices[gui_arch.result]

    # Filter
    funks = bv.functions
    if rename_only_unknowns:
        funks = list(filter(lambda x: x.name.startswith('sub_'), funks))

    log_info(f'{len(funks)} functions found', logger=logger)

    # Do the magic
    guess(bv, funks, tests_name, prefix=prefix, add_comment=add_comment, timeout=2, m_arch=m_arch,
          multi=True)


def cmd_run_on_function(bv, funk):
    log_info(f'{funk.name} ({funk.calling_convention.name})',
             logger='binja_sibyl.cmd_run_on_function')

    test_groups = list(sibyl.config.config.available_tests.keys())

    m_arch = ARCH_MAP[bv.arch.name]

    gui_label_options = LabelField('Options:')
    gui_tests = ChoiceField('Tests:', test_groups)
    gui_prefix = TextLineField('Function prefix:')
    gui_comment = ChoiceField('Add comment:', ('Yes', 'No'))
    gui_arch = ChoiceField('Architecture:', ARCHS, default=ARCHS.index(m_arch))

    ret = get_form_input(
        (gui_label_options, gui_tests, gui_prefix, gui_comment, gui_arch),
        'Sibyl'
    )

    if not ret:
        return

    tests_name = test_groups[gui_tests.result]
    add_comment = gui_comment.choices[gui_comment.result] == 'Yes'
    prefix = gui_prefix.result.strip()
    m_arch = gui_arch.choices[gui_arch.result]

    guess(bv, [funk], tests_name, prefix=prefix, add_comment=add_comment, timeout=3, m_arch=m_arch)


PluginCommand.register(
    name='Run Sibyl on whole file',
    description='Infer functions\' names from side effects',
    action=cmd_run
)

PluginCommand.register_for_function(
    name='Run Sibyl on current function',
    description='Infer function\'s name from its side effects',
    action=cmd_run_on_function
)
