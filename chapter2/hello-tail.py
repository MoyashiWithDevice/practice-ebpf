#!/usr/bin/python3
from bcc import BPF
import time

program = r"""
BPF_HASH(syscall);

RAW_TRACEPOINT_PROBE(sys_enter){
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u64 counter = 0;
    u64 *p;

    p = syscall.lookup(&uid);
    if (p != 0){
        counter = *p;
    }
    counter++;
    syscall.update(&uid, &counter);
    return 0;
}
"""

b = BPF(text=program)
while True:
    time.sleep(2)
    s=""
    for k,v in b["syscall"].items():
        s += f"ID {k.value}: {v.value}\t"
        print(s)