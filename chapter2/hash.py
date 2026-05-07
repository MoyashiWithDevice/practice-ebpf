#!/usr/bin/python3
from bcc import BPF
import time

program = r"""
BPF_HASH(counter_table);

int hello(struct pt_regs *ctx){
    u64 pid;
    u64 counter = 0;
    u64 *p;

    pid =  bpf_get_current_pid_tgid() >> 32;
    p = counter_table.lookup(&pid);
    if (p != 0){
        counter = *p;
    }
    counter++;
    counter_table.update(&pid, &counter);
    return 0;
}
"""

b = BPF(text=program)
openat_fn = b.get_syscall_fnname("openat")
write_fn = b.get_syscall_fnname("write")

b.attach_kprobe(event=openat_fn, fn_name="hello")
b.attach_kprobe(event=write_fn, fn_name="hello")

while True:
    time.sleep(2)
    s=""
    for k,v in b["counter_table"].items():
        s += f"PID {k.value}: {v.value}\t"
        print(s)