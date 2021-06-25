#!/usr/bin/env python3

# NFSv3 fuzzer based on boofuzz
# Designed for use with boofuzz v0.3.0
# Reference: https://github.com/jtpereyda/boofuzz-ftp/blob/master/ftp.py
# NFS Specification: RFC 1813

# Usage: python main.py fuzz

import re
import sys

import click
from boofuzz import *
from boofuzz.constants import DEFAULT_PROCMON_PORT
from boofuzz.utils.debugger_thread_simple import DebuggerThreadSimple
from boofuzz.utils.process_monitor_local import ProcessMonitorLocal

from defs import *
from log_monitor import LogMonitor

current_module = sys.modules[__name__]


class FuzzNfsException(Exception):
    pass


class RpcMessage(object):

    def __init__(self):
        pass

    def parse(self, data):
        pass

    def get_bytes(self):
        pass

    def get_contents(self):
        pass


def check_reply_code(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """
        Args:
            target (Target): Target with sock-like interface.
            fuzz_data_logger (ifuzz_logger.IFuzzLogger): Allows logging of test checks and passes/failures.
                Provided with a test case and test step already opened.
            session (Session): Session object calling post_send.
                Useful properties include last_send and last_recv.
            test_case_context (ProtocolSession): Context for test case-scoped data.
                :py:class:`TestCaseContext` :py:attr:`session_variables <TestCaseContext.session_variables>`
                values are generally set within a callback and referenced in elements via default values of type
                :py:class:`ReferenceValueTestCaseSession`.
            args: Implementations should include \\*args and \\**kwargs for forward-compatibility.
            kwargs: Implementations should include \\*args and \\**kwargs for forward-compatibility.
    """
    if test_case_context.previous_message.name == "__ROOT_NODE__":
        return
    else:
        try:
            fuzz_data_logger.log_info("Parsing reply contents: {0}".format(session.last_recv))
            parse_nfs_reply(session.last_recv)
        except FuzzNfsException as e:
            fuzz_data_logger.log_fail(str(e))
        fuzz_data_logger.log_pass()


def parse_nfs_reply(data):
    """
    Parse NFS reply and return reply code. Raise FuzzNfsException if reply is invalid.
    
    RFC 1813:
    
    2.5 Basic Data Types
          
    Args:
        data (bytes): Raw reply data
    """
    # RPC header(28 bytes) and NFS status(4 bytes)
    if len(data) < 28 + 4:
        raise FuzzNfsException("Invalid NFS reply, too short.")
    else:
        nfs_status = int.from_bytes(data[28:32], 'big')
        if nfs_status < 0 or nfs_status > 10008:
            raise FuzzNfsException("Invalid NFS reply, the status is invalid.")
        else:
            return nfs_status


@click.group()
def cli():
    pass


@click.command()
@click.option('--target-host', help='Host or IP address of target', prompt=True, default='192.168.2.185')
@click.option('--target-port', type=int, default=2049, help='Network port of target')
@click.option('--ssh-username', default='admin', help='SSH username, used by the log monitor', prompt=True)
@click.option('--ssh-port', default=22, help='SSH port of the target', prompt=True)
@click.option('--test-case-index', help='Test case index', type=str)
@click.option('--test-case-name', help='Name of node or specific test case')
@click.option('--csv-out', help='Output to CSV file')
@click.option('--sleep-between-cases', help='Wait time between test cases (floating point)', type=float, default=0)
@click.option('--procmon-host', help='Process monitor port host or IP')
@click.option('--procmon-port', type=int, default=DEFAULT_PROCMON_PORT, help='Process monitor port')
@click.option('--procmon-start', help='Process monitor start command')
@click.option('--procmon-capture', is_flag=True, help='Capture stdout/stderr from target process upon failure')
@click.option('--tui/--no-tui', help='Enable/disable TUI')
@click.option('--text-dump/--no-text-dump', help='Enable/disable full text dump of logs', default=False)
@click.option('--feature-check', is_flag=True, help='Run a feature check instead of a fuzz test', default=False)
@click.option('--log-monitor', is_flag=True, help='Use the custom log monitor based on ssh', default=False)
@click.argument('target_cmdline', nargs=-1, type=click.UNPROCESSED)
def fuzz(target_cmdline, target_host, target_port, ssh_username, ssh_port,
         test_case_index, test_case_name, csv_out, sleep_between_cases,
         procmon_host, procmon_port, procmon_start, procmon_capture, tui, text_dump, feature_check, log_monitor):
    local_procmon = None
    if len(target_cmdline) > 0 and procmon_host is None:
        local_procmon = ProcessMonitorLocal(crash_filename="boofuzz-crash-bin",
                                            proc_name=None,  # "proftpd",
                                            pid_to_ignore=None,
                                            debugger_class=DebuggerThreadSimple,
                                            level=1)

    fuzz_loggers = []
    if text_dump:
        fuzz_loggers.append(FuzzLoggerText())
    elif tui:
        fuzz_loggers.append(FuzzLoggerCurses())
    if csv_out is not None:
        f = open('ftp-fuzz.csv', 'wb')
        fuzz_loggers.append(FuzzLoggerCsv(file_handle=f))

    procmon_options = {}
    if procmon_start is not None:
        procmon_options['start_commands'] = [procmon_start]
    if target_cmdline is not None:
        procmon_options['start_commands'] = [list(target_cmdline)]
    if procmon_capture:
        procmon_options['capture_output'] = True

    if local_procmon is not None or procmon_host is not None:
        if procmon_host is not None:
            procmon = ProcessMonitor(procmon_host, procmon_port)
        else:
            procmon = local_procmon
        procmon.set_options(**procmon_options)
        monitors = [procmon]
    else:
        procmon = None
        monitors = []

    if log_monitor:
        monitors.append(LogMonitor(target_host, ssh_port, ssh_username))

    start = None
    end = None
    fuzz_only_one_case = None
    if test_case_index is None:
        start = 1
    elif "-" in test_case_index:
        start, end = test_case_index.split("-")
        if not start:
            start = 1
        else:
            start = int(start)
        if not end:
            end = None
        else:
            end = int(end)
    else:
        fuzz_only_one_case = int(test_case_index)

    connection = TCPSocketConnection(target_host, target_port)

    session = Session(
        target=Target(
            connection=connection,
            monitors=monitors,
        ),
        fuzz_loggers=fuzz_loggers,
        sleep_time=sleep_between_cases,
        index_start=start,
        index_end=end,
    )

    initialize_nfs(session)

    if feature_check:
        session.feature_check()
    elif fuzz_only_one_case is not None:
        session.fuzz_single_case(mutant_index=fuzz_only_one_case)
    elif test_case_name is not None:
        session.fuzz_by_name(test_case_name)
    else:
        session.fuzz()

    if procmon is not None:
        procmon.stop_target()


def initialize_nfs(session):
    null = _rpc_cmd('NULL')
    getattribute = _rpc_cmd('GETATTR')
    lookup = _rpc_cmd('LOOKUP')
    access = _rpc_cmd('ACCESS')
    readdirplus = _rpc_cmd('READDIRPLUS')
    fsstat = _rpc_cmd('FSSTAT')
    # fsinfo = 
    # pathconf = 

    session.connect(getattribute, callback=check_reply_code)
    session.connect(null, callback=check_reply_code)
    session.connect(lookup, callback=check_reply_code)
    session.connect(access, callback=check_reply_code)
    session.connect(readdirplus, callback=check_reply_code)
    session.connect(fsstat, callback=check_reply_code)


def _rpc_cmd(proc_name='NULL'):
    return Request(f'RPC-Request-{proc_name}', children=(
        Block("RPC-Header", children=(
            Word('last-fragment', default_value=0x8000, endian='>', fuzzable=False),
            Size('fragment-length', block_name='RPC-Body', endian='>', length=2, fuzzable=False),
        )),
        Block('RPC-Body', children=(
            DWord('xid', default_value=0x5756a477, endian='>', fuzzable=True),
            # Message Type: Call(0)
            DWord('message-type', default_value=0, endian='>', fuzzable=False),
            # RPC Version: 2
            DWord('rpc-version', default_value=2, endian='>', fuzzable=False),
            # Program: NFS(100003)
            DWord('program', default_value=100003, endian='>', fuzzable=False),
            # Program Version: 3
            DWord('program-version', default_value=3, endian='>', fuzzable=False),
            # Procedure: GETATTR/LOOKUP/SETATTR...
            DWord('procedure', default_value=NFS_PROC_CODES[proc_name], endian='>', fuzzable=False),
            Bytes(
                'credentials', 
                default_value=b"\x00\x00\x00\x01\x00\x00\x00\x48\x00\x00\x00\x00\x00\x00\x00\x04" \
                              b"\x6b\x61\x6c\x69\x00\x00\x03\xe8\x00\x00\x03\xe8\x00\x00\x00\x0c" \
                              b"\x00\x00\x00\x18\x00\x00\x00\x19\x00\x00\x00\x1b\x00\x00\x00\x1d" \
                              b"\x00\x00\x00\x1e\x00\x00\x00\x2c\x00\x00\x00\x2e\x00\x00\x00\x6d" \
                              b"\x00\x00\x00\x77\x00\x00\x00\x85\x00\x00\x00\x8d\x00\x00\x03\xe8",

                fuzzable=False
            ),
            Bytes(
                'verifier',
                default_value=b'\x00\x00\x00\x00\x00\x00\x00\x00',
                fuzzable=False
            ),

            # Call the corresponse function to get an NFS block
            getattr(current_module, f'_nfs_proc_{proc_name.lower()}')(),
        )),
    ))


def _nfs_proc_null():
    return Block('Empty-Block')

def _nfs_proc_getattr():
    # nfs object
    return Block('NFS-GETATTR', children=(
        _nfs_object(),
    ))

def _nfs_proc_setattr():
    return Block('NFS-SETATTR', children=(
        _nfs_object(),
        _nfs_new_attributes(),
        DWord('guard', default_value=0x0, endian='>', fuzzable=True)
    ))

def _nfs_proc_lookup():
    return Block('NFS-LOOKUP', children=(
        # what
        # -- dir
        Size('dir-length', block_name='filehandle', endian='>', length=4, fuzzable=False),
        Bytes(
            'filehandle', size=28, fuzzable=True,
            default_value=b'\x01\x00\x07\x00\x00\x01\x00\x00\x00\x00\x00\x00\xef\x40\xe7\x82' \
                          b'\xae\x34\x01\xab\x00\x00\x00\x00\x00\x00\x00\x00',
        ),
        # -- name
        Size('name-length', block_name='contents', endian='>', length=4, fuzzable=False),
        String('contents', default_value='.Trash', encoding='ascii', fuzzable=True),

        # TODO: calculate the correct padding
        Bytes('fill-bytes', size=2, default_value=b'\x00\x00', fuzzable=True),
    ))

def _nfs_proc_access():
    return Block('NFS-ACCESS', children=(
        Size('dir-length', block_name='filehandle', endian='>', length=4, fuzzable=False),
        Bytes(
            'filehandle', size=28, fuzzable=True,
            default_value=b'\x01\x00\x07\x00\x00\x01\x00\x00\x00\x00\x00\x00\xef\x40\xe7\x82' \
                          b'\xae\x34\x01\xab\x00\x00\x00\x00\x00\x00\x00\x00',
        ),
        DWord('check-access', default_value=0x1f, endian='>', fuzzable=True),
    ))

def _nfs_proc_read():
    return Block('NFS-READ', children=(
        _nfs_object(),
        QWord('offset', default_value=0, endian='>', fuzzable=True),
        DWord('count', default_value=6, endian='>', fuzzable=True),
    ))

def _nfs_proc_write():
    return Block('NFS-WRITE', children=(
        _nfs_object(),
        QWord('offset', default_value=0, endian='>', fuzzable=True),
        DWord('count', default_value=6, endian='>', fuzzable=True),
        DWord('stable', default_value=2, endian='>', fuzzable=True),
        Block('data', children=(
            Size('length', block_name='contents', endian='>', length=4, fuzzable=False),
            RandomData('contents', default_value=b'\x68\x65\x6c\x6c\x6f\x0a', fuzzable=True),
        ))
    ))

def _nfs_proc_create():
    return Block('NFS-CREATE', children=(
        # where
        # -- dir
        Size('dir-length', block_name='filehandle', endian='>', length=4, fuzzable=False),
        Bytes(
            'filehandle', size=28, fuzzable=True,
            default_value=b'\x01\x00\x07\x00\x00\x01\x00\x00\x00\x00\x00\x00\xef\x40\xe7\x82' \
                          b'\xae\x34\x01\xab\x00\x00\x00\x00\x00\x00\x00\x00',
        ),
        # -- name
        Size('name-length', block_name='contents', endian='>', length=4, fuzzable=False),
        String('contents', default_value='abcdabcd', encoding='ascii', fuzzable=True),

        DWord('create-mode', default_value=0, endian='>', fuzzalbe=True),
        _nfs_object()
    ))

def _nfs_proc_mkdir():
    return Block('NFS-MKDIR', children=(
        # where
        # -- dir
        Size('dir-length', block_name='filehandle', endian='>', length=4, fuzzable=False),
        Bytes(
            'filehandle', size=28, fuzzable=True,
            default_value=b'\x01\x00\x07\x00\x00\x01\x00\x00\x00\x00\x00\x00\xef\x40\xe7\x82' \
                          b'\xae\x34\x01\xab\x00\x00\x00\x00\x00\x00\x00\x00',
        ),

        # -- name
        Size('name-length', block_name='contents', endian='>', length=4, fuzzable=False),
        String('contents', default_value='abcdabcd', encoding='ascii', fuzzable=True),

        # attributes
        _nfs_new_attributes()
    ))

def _nfs_proc_symlink():
    return Block('NFS-SYMLINK', children=(
        # where
        # -- dir
        Size('dir-length', block_name='filehandle', endian='>', length=4, fuzzable=False),
        Bytes(
            'filehandle', size=28, fuzzable=True,
            default_value=b'\x01\x00\x07\x00\x00\x01\x00\x00\x00\x00\x00\x00\xef\x40\xe7\x82' \
                          b'\xae\x34\x01\xab\x00\x00\x00\x00\x00\x00\x00\x00',
        ),

        # -- name
        Size('name-length', block_name='contents', endian='>', length=4, fuzzable=False),
        String('contents', default_value='abcdabcd', encoding='ascii', fuzzable=True),

        # attributes
        _nfs_new_attributes(),

        # To
        Size('to-name-length', block_name='contents', endian='>', length=4, fuzzable=False),
        String('to-contents', default_value='lkjsdf', encoding='ascii', fuzzable=True),
    ))

def _nfs_proc_mknod():
    pass

def _nfs_proc_remove():
    return Block('NFS-REMOVE', children=(
        _nfs_object()
    ))

def _nfs_proc_rmdir():
    return Block('NFS-RMDIR', children=(
        _nfs_object()
    ))

def _nfs_proc_rename():
    return Block('NFS-RENAME', children=(
        # from
        _nfs_object(),
        # to
        _nfs_object(),
    ))

def _nfs_proc_link():
    pass

def _nfs_proc_readdir():
    pass

def _nfs_proc_readdirplus():
    return Block('NFS-READDIRPLUS', children=(
        # -- dir
        Size('dir-length', block_name='filehandle', endian='>', length=4, fuzzable=False),
        Bytes(
            'filehandle', size=28, fuzzable=True,
            default_value=b'\x01\x00\x07\x00\x00\x01\x00\x00\x00\x00\x00\x00\xef\x40\xe7\x82' \
                          b'\xae\x34\x01\xab\x00\x00\x00\x00\x00\x00\x00\x00',
        ),
        QWord('cookie', default_value=0, endian='>', fuzzable=True),
        QWord('verifier', default_value=0, endian='>', fuzzable=True),
        DWord('dircount', default_value=512, endian='>', fuzzable=True),
        DWord('maxcount', default_value=4096, endian='>', fuzzable=True),
    ))

def _nfs_proc_fsstat():
    return _nfs_object()

def _nfs_proc_fsinfo():
    pass

def _nfs_proc_pathconf():
    pass

def _nfs_proc_commit():
    pass

def _nfs_object(filehandle=None):
    return Block('NFS-Object', children=(
        Size('length', block_name='filehandle', endian='>', length=4, fuzzable=False),
        Bytes(
            'filehandle', size=28, fuzzable=True,
            default_value=b'\x01\x00\x07\x00\x00\x01\x00\x00\x00\x00\x00\x00\xef\x40\xe7\x82' \
                          b'\xae\x34\x01\xab\x00\x00\x00\x00\x00\x00\x00\x00',
        ),
    ))

def _nfs_new_attributes():
    return Block('NFS-NEW-ATTRIBUTES', children=(
        Block('mode', children=(
            DWord('set-it', default_value=0x1, endian='>', fuzzable=True),
            DWord('mode-value', default_value=0x01ed, endian='>', fuzzable=True),
        )),
        DWord('uid', default_value=0x0, endian='>', fuzzable=True),
        DWord('gid', default_value=0x0, endian='>', fuzzable=True),
        DWord('size', default_value=0x0, endian='>', fuzzable=True),
        DWord('atime', default_value=0x0, endian='>', fuzzable=True),
        DWord('mtime', default_value=0x0, endian='>', fuzzable=True),
    ))


cli.add_command(fuzz)

if __name__ == "__main__":
    cli()
