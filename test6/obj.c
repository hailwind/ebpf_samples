#include "vmlinux.h"
#include "bpf_helpers.h"

// Communication channel between the kprobe and the kretprobe.
// Holds a pointer to the nf_conn in the hot path (kprobe) and
// reads + deletes it in the kretprobe.
struct bpf_map_def SEC("maps/currct") currct = {
  .type = BPF_MAP_TYPE_PERCPU_HASH,
  .key_size = sizeof(u32),
  .value_size = sizeof(struct nf_conn *),
  .max_entries = 2048,
};

// // Top half of the update sampler. Stash the nf_conn pointer to later process
// // in a kretprobe after the counters have been updated.
// SEC("kprobe/__nf_ct_refresh_acct")
// int kprobe____nf_ct_refresh_acct(struct pt_regs *ctx) {

//   struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);

//   u32 pid = bpf_get_current_pid_tgid();

//   printt("i pid: %u ctp: %p ct: %p", pid, &ct ,ct);
//   // stash the conntrack pointer for lookup on return
//   bpf_map_update_elem(&currct, &pid, &ct, BPF_ANY);

//   return 0;
// }

// Bottom half of the update sampler. Extract accounting data from the nf_conn.
SEC("kretprobe/__nf_ct_refresh_acct")
int kretprobe____nf_ct_refresh_acct(struct pt_regs *ctx) {

  struct nf_conn *ct = (struct nf_conn *) PT_REGS_PARM1(ctx);
  u32 pid = bpf_get_current_pid_tgid();
  // u64 ts = bpf_ktime_get_ns();

  // Look up the conntrack structure stashed by the kprobe.
  // struct nf_conn *ctp;
  // ctp = bpf_map_lookup_elem(&currct, &pid);
  // if (ctp == 0) {
  //   printt("e ctp==0 pid: %u ctp: %p", pid, ctp);
  //   return 0;
  // }
  // struct nf_conn *ct;
  // ct=ctp;
  u16 cpu;
  bpf_probe_read(&cpu, sizeof(cpu), &ct->cpu);
  printt("e pid: %u cpu: %u ct: %p",pid, cpu, ct);
  // Dereference and delete from the stash table.
  // struct nf_conn *ct;
  // ct = (struct nf_conn *) *ctp;
  // u32 v;
  // bpf_probe_read(&v, sizeof(v), &ct->mark);

  // bpf_map_delete_elem(&currct, &pid);
  // printt("v: %u",v);

  return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
