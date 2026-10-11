#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <uapi/linux/ptrace.h>

// Define BPF hash maps and arrays
BPF_HASH(counter_table);                // Map to store user counters
BPF_HASH(permitted_processes_map, u64); // Map to store permitted processes
BPF_HASH(protected_inodes_map, u64);    // Map to store protected inodes
BPF_ARRAY(epoch_ts_map, u64, 1);        // Array to store epoch timestamp
BPF_PERF_OUTPUT(output);                // Perf output to send data to user space

#define OP_READ   0
#define OP_WRITE  1
#define OP_UNLINK 2
#define OP_RENAME 3
#define OP_RMDIR  4

struct data_t {
  u64 uid;              // User ID
  u32 thread_pid;       // Thread PID
  u64 thread_gpid;      // Thread Group PID
  u64 hooked_inode;     // Inode of the file being accessed
  u64 protected_inode;  // Protected inode
  u64 timestamp;        // Timestamp
  u64 counter;          // Counter
  char hooked_filename[64]; // Filename of the file being accessed
  int auth;             // Authorized
  u32 op;               // Operation being attempted
};

static __always_inline void read_dentry_name(char *dst, struct dentry *dentry) {
  if (dentry != NULL && dentry->d_name.name != NULL) {
    bpf_probe_read_kernel(dst, 64, dentry->d_name.name);
  }
}

static __always_inline int scylla_decide(void *ctx, u64 hooked_inode, struct dentry *dentry, u32 op) {
  u64 boot_ebpf_ts = bpf_ktime_get_ns();
  struct data_t data = {};
  int index = 0;
  u64 counter = 0;
  u64 *boot_epoch_ts = epoch_ts_map.lookup(&index);
  u64 *inode_ptr;
  u64 *permitted_process_ptr;
  u64 tgid;

  if (!boot_epoch_ts)
    return 0;

  inode_ptr = protected_inodes_map.lookup(&hooked_inode);
  if (inode_ptr == NULL)
    return 0;

  data.hooked_inode = hooked_inode;
  data.protected_inode = *inode_ptr;
  data.op = op;
  data.timestamp = *boot_epoch_ts + boot_ebpf_ts;
  read_dentry_name(data.hooked_filename, dentry);

  tgid = bpf_get_current_pid_tgid();
  data.thread_pid = tgid;
  data.thread_gpid = tgid >> 32;
  data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  permitted_process_ptr = permitted_processes_map.lookup(&data.thread_gpid);
  if (permitted_process_ptr == NULL) {
    data.auth = 0;
    output.perf_submit(ctx, &data, sizeof(data));
    bpf_send_signal(9);
    return -EPERM;
  }

  data.auth = 1;
  {
    u64 *counter_ptr = counter_table.lookup(&data.uid);
    if (counter_ptr != 0) {
      counter = *counter_ptr;
    }
    counter++;
    counter_table.update(&data.uid, &counter);
    data.counter = counter;
  }
  output.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

static __always_inline int scylla_check_dentry(void *ctx, struct dentry *dentry, u32 op) {
  struct inode *inode;

  if (dentry == NULL)
    return 0;

  inode = dentry->d_inode;
  if (inode == NULL)
    return 0;

  return scylla_decide(ctx, inode->i_ino, dentry, op);
}

static __always_inline int scylla_check_file(void *ctx, struct file *file, u32 op) {
  if (file == NULL || file->f_inode == NULL)
    return 0;

  return scylla_decide(ctx, file->f_inode->i_ino, file->f_path.dentry, op);
}

int protected_file(struct pt_regs *ctx, struct file *file) {
  scylla_check_file(ctx, file, OP_READ);
  return 0;
}

int protected_file_write(struct pt_regs *ctx, struct file *file) {
  scylla_check_file(ctx, file, OP_WRITE);
  return 0;
}

#ifdef SCYLLA_USE_LSM
LSM_PROBE(inode_unlink, struct inode *dir, struct dentry *dentry) {
  return scylla_check_dentry(ctx, dentry, OP_UNLINK);
}

LSM_PROBE(inode_rmdir, struct inode *dir, struct dentry *dentry) {
  return scylla_check_dentry(ctx, dentry, OP_RMDIR);
}

LSM_PROBE(inode_rename, struct inode *old_dir, struct dentry *old_dentry,
          struct inode *new_dir, struct dentry *new_dentry) {
  int rc = scylla_check_dentry(ctx, old_dentry, OP_RENAME);
  if (rc)
    return rc;
  return scylla_check_dentry(ctx, new_dentry, OP_RENAME);
}
#endif

#ifdef SCYLLA_USE_KPROBE_TAMPER
int hook_security_inode_unlink(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry) {
  scylla_check_dentry(ctx, dentry, OP_UNLINK);
  return 0;
}

int hook_security_inode_rmdir(struct pt_regs *ctx, struct inode *dir, struct dentry *dentry) {
  scylla_check_dentry(ctx, dentry, OP_RMDIR);
  return 0;
}

int hook_security_inode_rename(struct pt_regs *ctx, struct inode *old_dir,
                               struct dentry *old_dentry, struct inode *new_dir,
                               struct dentry *new_dentry, unsigned int flags) {
  scylla_check_dentry(ctx, old_dentry, OP_RENAME);
  scylla_check_dentry(ctx, new_dentry, OP_RENAME);
  return 0;
}
#endif
