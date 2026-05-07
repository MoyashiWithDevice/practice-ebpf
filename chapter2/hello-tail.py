#!/usr/bin/python3
from bcc import BPF
import time

program = r"""
BPF_HASH(syscall);

int hello(struct bpf_raw_tracepoint_args *ctx){
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

prog_array = b.get_table("syscall")

b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    time.sleep(2)
    s=""
    for k,v in b["syscall"].items():
        s += f"ID {k.value}: {v.value}\t"
        print(s)