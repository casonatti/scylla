from bcc import BPF
from ctypes import *
from Log import *
from datetime import datetime
import array
import fcntl
import time
import os

OP_NAMES = {
  0: "read",
  1: "write",
  2: "delete",
  3: "rename",
  4: "rmdir",
}

# linux/fs.h: FS_IOC_GETFLAGS / FS_IOC_SETFLAGS / FS_IMMUTABLE_FL
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602
FS_IMMUTABLE_FL = 0x00000010

LSM_HOOKS = ("inode_unlink", "inode_rename", "inode_rmdir")
TAMPER_KPROBES = (
  ("security_inode_unlink", "hook_security_inode_unlink"),
  ("security_inode_rename", "hook_security_inode_rename"),
  ("security_inode_rmdir", "hook_security_inode_rmdir"),
)


def bpf_lsm_active():
  try:
    with open("/sys/kernel/security/lsm", "r") as lsm_file:
      return "bpf" in [name.strip() for name in lsm_file.read().split(",")]
  except OSError:
    return False


class Scylla():
  def __init__(self, log):
    self.log = log
    self.stop = True
    self.lsm_enabled = False
    self.tamper_kprobes = []
    self.immutable_applied = {}

    # Get timestamp epoch at the boot time (bcc only offers timestamp counting since boot)
    current_epoch_ts = time.time_ns()
    boot_relative_ts = time.monotonic_ns()
    self.boot_epoch_ts = current_epoch_ts - boot_relative_ts

    program = "scylla_ebpf.c"
    use_lsm = bpf_lsm_active()
    cflags = ["-DSCYLLA_USE_LSM"] if use_lsm else ["-DSCYLLA_USE_KPROBE_TAMPER"]

    try:
      self.b = BPF(src_file = program, cflags = cflags)
      self.lsm_enabled = use_lsm
    except Exception as exc:
      if not use_lsm:
        raise
      print("Failed to load BPF LSM hooks, falling back to kprobes: " + str(exc))
      self.b = BPF(src_file = program, cflags = ["-DSCYLLA_USE_KPROBE_TAMPER"])
      self.lsm_enabled = False

    self.b.attach_kprobe(event = "vfs_read", fn_name = "protected_file")
    self.b.attach_kprobe(event = "vfs_write", fn_name = "protected_file_write")

    if not self.lsm_enabled:
      for event, fn_name in TAMPER_KPROBES:
        self.b.attach_kprobe(event = event, fn_name = fn_name)
        self.tamper_kprobes.append(event)

    self.map_populating()
    self.apply_immutable_guard()
    self.log_protection_mode()

    # Link user and kernel spaces for gathering info
    self.b["output"].open_perf_buffer(self.log_event)

  def run(self):
    self.stop = False

    # Keep on checking for new data
    while not self.stop:
      try:
        self.b.perf_buffer_poll(timeout = 0)
      except KeyboardInterrupt:
        exit(0)

  def close(self):
    self.b.detach_kprobe(event = "vfs_read")
    self.b.detach_kprobe(event = "vfs_write")

    for event in self.tamper_kprobes:
      self.b.detach_kprobe(event = event)

    if self.lsm_enabled:
      for hook in LSM_HOOKS:
        try:
          self.b.detach_lsm(fn_name = hook)
        except Exception:
          pass

    self.clear_immutable_guard()
    self.stop = True

  def log_protection_mode(self):
    log_timestamp = datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M")
    if self.lsm_enabled:
      self.log.append(
        f"[{log_timestamp}] [INFO] Delete/rename protection enabled via eBPF LSM hooks"
      )
      return

    self.log.append(
      f"[{log_timestamp}] [WARN] BPF LSM is inactive; delete/rename is enforced with "
      "security_* kprobes plus immutable file flags. Add bpf to the kernel lsm= list "
      "and reboot for eBPF denial before the filesystem change."
    )

  # Get info from eBPF program and generate logs
  def log_event(self, cpu, data, size):
    data = self.b["output"].event(data)
    
    gui_pid = os.getpid()
    
    if data.thread_gpid == gui_pid:
      return

    filename = data.hooked_filename.decode("utf-8", errors = "replace").split("\x00", 1)[0]
    operation = OP_NAMES.get(int(data.op), "access")

    time_ns = data.timestamp
    time_s = time_ns / 1e9
    dt = datetime.fromtimestamp(time_s)
    log_timestamp = dt.strftime("%Y-%m-%d %H:%M")
    
    if data.auth:
      log_text = f"[{log_timestamp}] [ALLOWED] File [{filename}] {operation} by GPID [{data.thread_gpid}]"
    else:
      log_text = f"[{log_timestamp}] [DENIED] GPID [{data.thread_gpid}] was blocked trying to {operation} file [{filename}]"

    self.log.append(log_text)

  def map_populating(self):
    # user/kernel -space map association
    i_map = self.b["protected_inodes_map"]
    ts_map = self.b["epoch_ts_map"]
    permitted_processes_map = self.b["permitted_processes_map"]

    # Populating maps
    ts_map[c_int(0)] = c_uint64(self.boot_epoch_ts)

    permitted_pids_file = open("../config/permitted_pids", "r")
    line = permitted_pids_file.readline()
    while line:
      line = line.strip()
      if line:
        print("Copying " + line + " to eBPF map [permitted_processes_map]")
        permitted_processes_map[c_uint64(int(line))] = c_uint64(int(line))
      line = permitted_pids_file.readline()

    inode_list_file = open("../config/protected_inodes", "r")
    line = inode_list_file.readline()
    while line:
      temp = line.split(None, 1)
      if temp:
        print("Copying " + line.rstrip() + " to eBPF map [inode_map]")
        i_map[c_uint64(int(temp[0]))] = c_uint64(int(temp[0]))
      line = inode_list_file.readline()

  def protected_paths(self):
    paths = []
    with open("../config/protected_inodes", "r") as inode_list_file:
      for line in inode_list_file:
        temp = line.split(None, 1)
        if len(temp) < 2:
          continue
        path = temp[1].strip()
        if os.path.isfile(path):
          paths.append(path)
    return paths

  def apply_immutable_guard(self):
    if self.lsm_enabled:
      return

    paths = self.protected_paths()
    if not paths:
      log_timestamp = datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M")
      self.log.append(
        f"[{log_timestamp}] [WARN] No resolvable protected file paths; "
        "re-add files in the GUI so the immutable fallback can pin them, "
        "or enable BPF LSM for inode-only denial."
      )
      return

    for path in paths:
      try:
        flags = self._get_fs_flags(path)
        if flags & FS_IMMUTABLE_FL:
          continue
        self._set_fs_flags(path, flags | FS_IMMUTABLE_FL)
        self.immutable_applied[path] = flags
        print("Set immutable flag on " + path)
      except OSError as exc:
        print("Failed to set immutable flag on " + path + ": " + str(exc))

  def clear_immutable_guard(self):
    for path, original_flags in list(self.immutable_applied.items()):
      try:
        self._set_fs_flags(path, original_flags)
        print("Cleared immutable flag on " + path)
      except OSError as exc:
        print("Failed to clear immutable flag on " + path + ": " + str(exc))
      finally:
        self.immutable_applied.pop(path, None)

  def _get_fs_flags(self, path):
    fd = os.open(path, os.O_RDONLY)
    try:
      flags = array.array("l", [0])
      fcntl.ioctl(fd, FS_IOC_GETFLAGS, flags, True)
      return flags[0]
    finally:
      os.close(fd)

  def _set_fs_flags(self, path, flags):
    fd = os.open(path, os.O_RDONLY)
    try:
      buf = array.array("l", [flags])
      fcntl.ioctl(fd, FS_IOC_SETFLAGS, buf, True)
    finally:
      os.close(fd)
