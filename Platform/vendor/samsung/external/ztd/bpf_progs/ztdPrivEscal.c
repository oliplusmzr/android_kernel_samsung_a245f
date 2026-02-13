#include <stdbool.h>
#include "bpf_shared.h"
#include "bpf_read.h"
#include <ztd_events.h>
#include <ztd_priv_escal_shared.h>
#include <ztd_sc_shared.h>

#define DEBUG 0
#define DEBUG_ENTRY 0

DEFINE_BPF_MAP_GRW(priv_escal_data_map, LRU_HASH, uint64_t, proc_event_raw_t, 1024, AID_SYSTEM);
DEFINE_BPF_MAP_GRW(proc_event_map, PERCPU_ARRAY, uint32_t, proc_event_raw_t, 1, AID_SYSTEM);
DEFINE_BPF_RINGBUF_EXT(event_noti_ringbuf, event_noti_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
DEFINE_BPF_SHARED_MAP_GRW(offsets_frame_map, ARRAY, uint32_t, offsets_frame_buf_t, 1, AID_SYSTEM);
DEFINE_BPF_SHARED_MAP_GRW(proc_info_map, LRU_HASH, uint32_t, proc_info_t, 32768, AID_SYSTEM);

#define MAX_PATH_DEPTH 128

#define TRACE_EVENT_SYS_ENTER_PREFIX 1000
#define TRACE_EVENT_SYS_EXIT_PREFIX 2000

typedef sched_process_exit_data_t sched_process_exit_args_t;

static int (*bpf_probe_read_kernel_str)(void* dst, int size, const void* safe_ptr) = (void*)BPF_FUNC_probe_read_kernel_str;
static bool isSyscallForCredChange(int nr_syscall);
static bool isCredentialModified();

static inline __always_inline void updatePathName(struct path *path, char pathName[], offsets_frame_buf_t *ofb) {
    struct dentry *d_current = BPF_READ_AT(path, dentry, ofb->offsets[OFFSET_DENTRY_IN_PATH]);

    uint12_t idx = { .value = 0 };
    for (int d = 0; d < MAX_PATH_DEPTH ; d++) {
        struct dentry *d_parent = BPF_READ_AT(d_current, d_parent, ofb->offsets[OFFSET_D_PARENT_IN_DENTRY]);
        if (!d_current) {
            break;
        }
        struct qstr d_name = BPF_READ_AT(d_current, d_name, ofb->offsets[OFFSET_D_NAME_IN_DENTRY]);
        const unsigned char *name = BPF_READ_AT(&d_name, name, ofb->offsets[OFFSET_NAME_IN_QSTR]);
        if (d_parent == d_current) {
            if (idx.value <= (MAX_FP_LEN - MAX_FN_LEN)) {
                bpf_probe_read_kernel_str(&pathName[idx.value], MAX_FN_LEN, (void *) name);
            }
            break;
        } else {
            if (idx.value > 0 && idx.value < (MAX_FP_LEN - 1)) {
                pathName[idx.value++] = '/';
            }
            int ret = 0;
            if (idx.value <= (MAX_FP_LEN - MAX_FN_LEN)) {
                ret = bpf_probe_read_kernel_str(&pathName[idx.value], MAX_FN_LEN, (void *) name);
            }
            if (ret > 1) {
                idx.value += (ret - 1);
            } else {
                break;
            }
        }
        d_current = d_parent;
    }
}

static inline __always_inline void updateCmdline(uint64_t args, char cmdline[]) {

    uint64_t argv_addr;
    uint12_t idx = { .value = 0 };
    for (int d = 0; d < MAX_PATH_DEPTH ; d++) {
        void *argv_ptr = POINTER_OF_USER_SPACE(args + (d * sizeof(void *)));
        if (!argv_ptr) {
            break;
        }
        bpf_probe_read_user(&argv_addr, sizeof(argv_addr), argv_ptr);
        if (!argv_addr) {
            break;
        }
        if (idx.value > 0 && idx.value < (MAX_FP_LEN - 1)) {
            cmdline[idx.value++] = ' ';
        }
        int ret = 0;
        if (idx.value <= (MAX_FP_LEN - MAX_FN_LEN)) {
            ret = bpf_probe_read_user_str(&cmdline[idx.value], MAX_FN_LEN, POINTER_OF_USER_SPACE(argv_addr));
        }
        if (ret > 1) {
            idx.value += (ret - 1);
        } else {
            break;
        }
    }
}

static inline __always_inline void onSyscallEnter(int event, sys_enter_data_t *args) {

    uint64_t event_time = bpf_ktime_get_boot_ns();
    uint32_t zero = 0; // Look-up Key
    offsets_frame_buf_t *ofb = bpf_offsets_frame_map_lookup_elem(&zero);
    if (!ofb) {
        return;
    }

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (!task) {
        return;
    }

    proc_event_raw_t* data = bpf_proc_event_map_lookup_elem(&zero);
    if (!data) {
        return;
    }

    data->event = event;
    data->event_time = event_time;

    int syscall = args->id;
    data->syscall = syscall;

    int exit_code = BPF_READ_AT(task, exit_code, ofb->offsets[OFFSET_EXIT_CODE_IN_TASK_STRUCT]);
    data->exit_code = exit_code;

    pid_t pid = BPF_READ_AT(task, pid, ofb->offsets[OFFSET_PID_IN_TASK_STRUCT]);
    data->tid = pid;

    pid_t tgid = BPF_READ_AT(task, tgid, ofb->offsets[OFFSET_TGID_IN_TASK_STRUCT]);
    data->pid = tgid;

    struct task_struct *real_parent = BPF_READ_AT(task, real_parent, ofb->offsets[OFFSET_REAL_PARENT_IN_TASK_STRUCT]);
    pid_t ptgid = BPF_READ_AT(real_parent, tgid, ofb->offsets[OFFSET_TGID_IN_TASK_STRUCT]);
    data->ppid = ptgid;

    struct cred *cred = (struct cred *)BPF_READ_AT(task, cred, ofb->offsets[OFFSET_CRED_IN_TASK_STRUCT]);
    kuid_t uid = BPF_READ_AT(cred, uid, ofb->offsets[OFFSET_UID_IN_CRED]);
    data->uid = uid.value;

    kgid_t gid = BPF_READ_AT(cred, gid, ofb->offsets[OFFSET_GID_IN_CRED]);
    data->gid = gid.value;

    kuid_t suid = BPF_READ_AT(cred, suid, ofb->offsets[OFFSET_SUID_IN_CRED]);
    data->suid = suid.value;

    kgid_t sgid = BPF_READ_AT(cred, sgid, ofb->offsets[OFFSET_SGID_IN_CRED]);
    data->sgid = sgid.value;

    kuid_t euid = BPF_READ_AT(cred, euid, ofb->offsets[OFFSET_EUID_IN_CRED]);
    data->euid = euid.value;

    kgid_t egid = BPF_READ_AT(cred, egid, ofb->offsets[OFFSET_EGID_IN_CRED]);
    data->egid = egid.value;

    kuid_t fsuid = BPF_READ_AT(cred, fsuid, ofb->offsets[OFFSET_FSUID_IN_CRED]);
    data->fsuid = fsuid.value;

    kgid_t fsgid = BPF_READ_AT(cred, fsgid, ofb->offsets[OFFSET_FSGID_IN_CRED]);
    data->fsgid = fsgid.value;

    struct fs_struct *fs = BPF_READ_AT(task, fs, ofb->offsets[OFFSET_FS_IN_TASK_STRUCT]);
    struct mm_struct *mm = BPF_READ_AT(task, mm, ofb->offsets[OFFSET_MM_IN_TASK_STRUCT]);
    struct file *exe_file = BPF_READ_AT(mm, exe_file, ofb->offsets[OFFSET_EXE_FILE_IN_MM_STRUCT]);
    struct path *pwd = BPF_READ_ADDR_AT(fs, pwd, ofb->offsets[OFFSET_PWD_IN_FS_STRUCT]);
    struct path *f_path = BPF_READ_ADDR_AT(exe_file, f_path, ofb->offsets[OFFSET_F_PATH_IN_FILE]);
    struct dentry *dentry = BPF_READ_AT(f_path, dentry, ofb->offsets[OFFSET_DENTRY_IN_PATH]);
    struct inode *d_inode = BPF_READ_AT(dentry, d_inode, ofb->offsets[OFFSET_D_INODE_IN_DENTRY]);
    struct timespec64 *i_atime = BPF_READ_ADDR_AT(d_inode, i_atime, ofb->offsets[OFFSET_I_ATIME_IN_INODE]);
    struct timespec64 *i_mtime = BPF_READ_ADDR_AT(d_inode, i_mtime, ofb->offsets[OFFSET_I_MTIME_IN_INODE]);
    struct timespec64 *i_ctime = BPF_READ_ADDR_AT(d_inode, i_ctime, ofb->offsets[OFFSET_I_CTIME_IN_INODE]);

    kuid_t owner_uid = BPF_READ_AT(d_inode, i_uid, ofb->offsets[OFFSET_I_UID_IN_INODE]);
    data->owner_uid = owner_uid.value;

    kgid_t owner_gid = BPF_READ_AT(d_inode, i_gid, ofb->offsets[OFFSET_I_GID_IN_INODE]);
    data->owner_gid = owner_gid.value;

    time64_t atime = BPF_READ_AT(i_atime, tv_sec, ofb->offsets[OFFSET_TV_SEC_IN_TIMESPEC64]);
    data->atime = atime;

    time64_t mtime = BPF_READ_AT(i_mtime, tv_sec, ofb->offsets[OFFSET_TV_SEC_IN_TIMESPEC64]);
    data->mtime = mtime;

    time64_t ctime = BPF_READ_AT(i_ctime, tv_sec, ofb->offsets[OFFSET_TV_SEC_IN_TIMESPEC64]);
    data->ctime = ctime;

    updatePathName(pwd, data->cwd, ofb);
    updatePathName(f_path, data->filepath, ofb);
    updateCmdline(args->args[1], data->cmdline);

#if DEBUG
    umode_t umode = BPF_READ_AT(d_inode, i_mode, ofb->offsets[OFFSET_I_MODE_IN_INODE]);

    bpf_printk("[ztd] PrivEscal.sys_enter :: event      = %d", event);
    bpf_printk("[ztd] PrivEscal.sys_enter :: event_time = %lu", event_time);
    bpf_printk("[ztd] PrivEscal.sys_enter :: event size = %d", sizeof(proc_event_raw_t));
    bpf_printk("[ztd] PrivEscal.sys_enter :: tid        = %d", pid);
    bpf_printk("[ztd] PrivEscal.sys_enter :: pid        = %d", tgid);
    bpf_printk("[ztd] PrivEscal.sys_enter :: ppid       = %d", ptgid);
    bpf_printk("[ztd] PrivEscal.sys_enter :: syscall    = %d", syscall);
    bpf_printk("[ztd] PrivEscal.sys_enter :: exit_code  = %d", exit_code);
    bpf_printk("[ztd] PrivEscal.sys_enter :: uid        = %u", *((int *) &uid));
    bpf_printk("[ztd] PrivEscal.sys_enter :: gid        = %u", *((int *) &gid));
    bpf_printk("[ztd] PrivEscal.sys_enter :: suid       = %u", *((int *) &suid));
    bpf_printk("[ztd] PrivEscal.sys_enter :: sgid       = %u", *((int *) &sgid));
    bpf_printk("[ztd] PrivEscal.sys_enter :: euid       = %u", *((int *) &euid));
    bpf_printk("[ztd] PrivEscal.sys_enter :: egid       = %u", *((int *) &egid));
    bpf_printk("[ztd] PrivEscal.sys_enter :: fsuid      = %u", *((int *) &fsuid));
    bpf_printk("[ztd] PrivEscal.sys_enter :: fsgid      = %u", *((int *) &fsgid));
    bpf_printk("[ztd] PrivEscal:sys_enter :: owner_uid  = %u", *((int *) &owner_uid));
    bpf_printk("[ztd] PrivEscal:sys_enter :: owner_gid  = %u", *((int *) &owner_gid));
    bpf_printk("[ztd] PrivEscal:sys_enter :: umode      = %u", umode);
    bpf_printk("[ztd] PrivEscal:sys_enter :: atime      = %ld", atime);
    bpf_printk("[ztd] PrivEscal:sys_enter :: mtime      = %ld", mtime);
    bpf_printk("[ztd] PrivEscal:sys_enter :: ctime      = %ld", ctime);
    bpf_printk("[ztd] PrivEscal.sys_enter :: cwd        = %s", data->cwd);
    bpf_printk("[ztd] PrivEscal.sys_enter :: filepath   = %s", data->filepath);
    bpf_printk("[ztd] PrivEscal.sys_enter :: cmdline    = %s", data->cmdline);
#endif

    uint64_t cpu_id = bpf_get_smp_processor_id();
    uint64_t key = (cpu_id & 0x00000000000000FF) << 56 | event_time;
#if DEBUG
    bpf_printk("[ztd] PrivEscal.sys_enter :: cpu_id = %lu, event_time = %lu, key = %lu", cpu_id, event_time, key);
#endif
    bpf_priv_escal_data_map_update_elem(&key, data, BPF_ANY);
    event_noti_t *noti = bpf_event_noti_ringbuf_reserve();
    if (!noti) {
#if DEBUG
        bpf_printk("[ztd] PrivEscal.sys_enter :: no ringbuf to reserve!");
#endif
        return;
    }
#if DEBUG
    bpf_printk("[ztd] PrivEscal.sys_enter :: noti->type = %d", args->id);
#endif
    noti->type = event;
    noti->key = key;
    bpf_event_noti_ringbuf_submit(noti);
}

static inline __always_inline void onSyscallExit(int event, sys_exit_data_t *args) {

    uint64_t event_time = bpf_ktime_get_boot_ns();
    uint32_t zero = 0; // Look-up Key
    offsets_frame_buf_t *ofb = bpf_offsets_frame_map_lookup_elem(&zero);
    if (!ofb) {
        return;
    }

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (!task) {
        return;
    }

    proc_event_raw_t* data = bpf_proc_event_map_lookup_elem(&zero);
    if (!data) {
        return;
    }

    data->event = event;
    data->event_time = event_time;

    int syscall = args->id;
    data->syscall = syscall;

    int exit_code = BPF_READ_AT(task, exit_code, ofb->offsets[OFFSET_EXIT_CODE_IN_TASK_STRUCT]);
    data->exit_code = exit_code;

    pid_t pid = BPF_READ_AT(task, pid, ofb->offsets[OFFSET_PID_IN_TASK_STRUCT]);
    data->tid = pid;

    pid_t tgid = BPF_READ_AT(task, tgid, ofb->offsets[OFFSET_TGID_IN_TASK_STRUCT]);
    data->pid = tgid;

    struct task_struct *real_parent = BPF_READ_AT(task, real_parent, ofb->offsets[OFFSET_REAL_PARENT_IN_TASK_STRUCT]);
    pid_t ptgid = BPF_READ_AT(real_parent, tgid, ofb->offsets[OFFSET_TGID_IN_TASK_STRUCT]);
    data->ppid = ptgid;

    struct cred *cred = (struct cred *)BPF_READ_AT(task, cred, ofb->offsets[OFFSET_CRED_IN_TASK_STRUCT]);
    kuid_t uid = BPF_READ_AT(cred, uid, ofb->offsets[OFFSET_UID_IN_CRED]);
    data->uid = uid.value;

    kgid_t gid = BPF_READ_AT(cred, gid, ofb->offsets[OFFSET_GID_IN_CRED]);
    data->gid = gid.value;

    kuid_t suid = BPF_READ_AT(cred, suid, ofb->offsets[OFFSET_SUID_IN_CRED]);
    data->suid = suid.value;

    kgid_t sgid = BPF_READ_AT(cred, sgid, ofb->offsets[OFFSET_SGID_IN_CRED]);
    data->sgid = sgid.value;

    kuid_t euid = BPF_READ_AT(cred, euid, ofb->offsets[OFFSET_EUID_IN_CRED]);
    data->euid = euid.value;

    kgid_t egid = BPF_READ_AT(cred, egid, ofb->offsets[OFFSET_EGID_IN_CRED]);
    data->egid = egid.value;

    kuid_t fsuid = BPF_READ_AT(cred, fsuid, ofb->offsets[OFFSET_FSUID_IN_CRED]);
    data->fsuid = fsuid.value;

    kgid_t fsgid = BPF_READ_AT(cred, fsgid, ofb->offsets[OFFSET_FSGID_IN_CRED]);
    data->fsgid = fsgid.value;

    struct fs_struct *fs = BPF_READ_AT(task, fs, ofb->offsets[OFFSET_FS_IN_TASK_STRUCT]);
    struct mm_struct *mm = BPF_READ_AT(task, mm, ofb->offsets[OFFSET_MM_IN_TASK_STRUCT]);
    struct file *exe_file = BPF_READ_AT(mm, exe_file, ofb->offsets[OFFSET_EXE_FILE_IN_MM_STRUCT]);
    struct path *pwd = BPF_READ_ADDR_AT(fs, pwd, ofb->offsets[OFFSET_PWD_IN_FS_STRUCT]);
    struct path *f_path = BPF_READ_ADDR_AT(exe_file, f_path, ofb->offsets[OFFSET_F_PATH_IN_FILE]);
    struct dentry *dentry = BPF_READ_AT(f_path, dentry, ofb->offsets[OFFSET_DENTRY_IN_PATH]);
    struct inode *d_inode = BPF_READ_AT(dentry, d_inode, ofb->offsets[OFFSET_D_INODE_IN_DENTRY]);
    struct timespec64 *i_atime = BPF_READ_ADDR_AT(d_inode, i_atime, ofb->offsets[OFFSET_I_ATIME_IN_INODE]);
    struct timespec64 *i_mtime = BPF_READ_ADDR_AT(d_inode, i_mtime, ofb->offsets[OFFSET_I_MTIME_IN_INODE]);
    struct timespec64 *i_ctime = BPF_READ_ADDR_AT(d_inode, i_ctime, ofb->offsets[OFFSET_I_CTIME_IN_INODE]);

    kuid_t owner_uid = BPF_READ_AT(d_inode, i_uid, ofb->offsets[OFFSET_I_UID_IN_INODE]);
    data->owner_uid = owner_uid.value;

    kgid_t owner_gid = BPF_READ_AT(d_inode, i_gid, ofb->offsets[OFFSET_I_GID_IN_INODE]);
    data->owner_gid = owner_gid.value;

    time64_t atime = BPF_READ_AT(i_atime, tv_sec, ofb->offsets[OFFSET_TV_SEC_IN_TIMESPEC64]);
    data->atime = atime;

    time64_t mtime = BPF_READ_AT(i_mtime, tv_sec, ofb->offsets[OFFSET_TV_SEC_IN_TIMESPEC64]);
    data->mtime = mtime;

    time64_t ctime = BPF_READ_AT(i_ctime, tv_sec, ofb->offsets[OFFSET_TV_SEC_IN_TIMESPEC64]);
    data->ctime = ctime;

    updatePathName(pwd, data->cwd, ofb);
    updatePathName(f_path, data->filepath, ofb);
    updateCmdline(args->ret, data->cmdline);

#if DEBUG
    umode_t umode = BPF_READ_AT(d_inode, i_mode, ofb->offsets[OFFSET_I_MODE_IN_INODE]);

    bpf_printk("[ztd] PrivEscal.sys_exit :: event      = %d", event);
    bpf_printk("[ztd] PrivEscal.sys_exit :: event_time = %lu", event_time);
    bpf_printk("[ztd] PrivEscal.sys_exit :: event size = %d", sizeof(proc_event_raw_t));
    bpf_printk("[ztd] PrivEscal.sys_exit :: tid        = %d", pid);
    bpf_printk("[ztd] PrivEscal.sys_exit :: pid        = %d", tgid);
    bpf_printk("[ztd] PrivEscal.sys_exit :: ppid       = %d", ptgid);
    bpf_printk("[ztd] PrivEscal.sys_exit :: syscall    = %d", syscall);
    bpf_printk("[ztd] PrivEscal.sys_exit :: exit_code  = %d", exit_code);
    bpf_printk("[ztd] PrivEscal.sys_exit :: uid        = %u", *((int *) &uid));
    bpf_printk("[ztd] PrivEscal.sys_exit :: gid        = %u", *((int *) &gid));
    bpf_printk("[ztd] PrivEscal.sys_exit :: suid       = %u", *((int *) &suid));
    bpf_printk("[ztd] PrivEscal.sys_exit :: sgid       = %u", *((int *) &sgid));
    bpf_printk("[ztd] PrivEscal.sys_exit :: euid       = %u", *((int *) &euid));
    bpf_printk("[ztd] PrivEscal.sys_exit :: egid       = %u", *((int *) &egid));
    bpf_printk("[ztd] PrivEscal.sys_exit :: fsuid      = %u", *((int *) &fsuid));
    bpf_printk("[ztd] PrivEscal.sys_exit :: fsgid      = %u", *((int *) &fsgid));
    bpf_printk("[ztd] PrivEscal:sys_exit :: owner_uid  = %u", *((int *) &owner_uid));
    bpf_printk("[ztd] PrivEscal:sys_exit :: owner_gid  = %u", *((int *) &owner_gid));
    bpf_printk("[ztd] PrivEscal:sys_exit :: umode      = %u", umode);
    bpf_printk("[ztd] PrivEscal:sys_exit :: atime      = %ld", atime);
    bpf_printk("[ztd] PrivEscal:sys_exit :: mtime      = %ld", mtime);
    bpf_printk("[ztd] PrivEscal:sys_exit :: ctime      = %ld", ctime);
    bpf_printk("[ztd] PrivEscal.sys_exit :: cwd        = %s", data->cwd);
    bpf_printk("[ztd] PrivEscal.sys_exit :: filepath   = %s", data->filepath);
    bpf_printk("[ztd] PrivEscal.sys_exit :: cmdline    = %s", data->cmdline);
#endif

    uint64_t cpu_id = bpf_get_smp_processor_id();
    uint64_t key = (cpu_id & 0x00000000000000FF) << 56 | event_time;
#if DEBUG
    bpf_printk("[ztd] PrivEscal.sys_enter :: cpu_id = %lu, event_time = %lu, key = %lu", cpu_id, event_time, key);
#endif
    bpf_priv_escal_data_map_update_elem(&key, data, BPF_ANY);
    event_noti_t *noti = bpf_event_noti_ringbuf_reserve();
    if (!noti) {
#if DEBUG
        bpf_printk("[ztd] PrivEscal.sys_enter :: no ringbuf to reserve!");
#endif
        return;
    }
#if DEBUG
    bpf_printk("[ztd] PrivEscal.sys_exit :: noti->type = %d", args->id);
#endif
    noti->type = event;
    noti->key = key;
    bpf_event_noti_ringbuf_submit(noti);
}

static bool inline __always_inline isSyscallForCredChange(int nr_syscall) {
    return (nr_syscall == GENERIC_SYSCALL_NR_SETREGID
            || nr_syscall == GENERIC_SYSCALL_NR_SETGID
            || nr_syscall == GENERIC_SYSCALL_NR_SETREUID
            || nr_syscall == GENERIC_SYSCALL_NR_SETUID
            || nr_syscall == GENERIC_SYSCALL_NR_SETRESUID
            || nr_syscall == GENERIC_SYSCALL_NR_SETRESGID
            || nr_syscall == GENERIC_SYSCALL_NR_SETFSUID
            || nr_syscall == GENERIC_SYSCALL_NR_SETFSGID);
}

static bool inline __always_inline isCredentialModified() {
    uint32_t zero = 0; // Look-up Key
    offsets_frame_buf_t *ofb = bpf_offsets_frame_map_lookup_elem(&zero);
    if (!ofb) {
        return false;
    }

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (!task) {
        return false;
    }
    pid_t tgid = BPF_READ_AT(task, tgid, ofb->offsets[OFFSET_TGID_IN_TASK_STRUCT]);

    uint32_t pi_key = tgid;
    proc_info_t *pi = bpf_proc_info_map_lookup_elem(&pi_key);
    if (!pi) {
        struct task_struct *real_parent = BPF_READ_AT(task, real_parent, ofb->offsets[OFFSET_REAL_PARENT_IN_TASK_STRUCT]);
        pid_t ptgid = BPF_READ_AT(real_parent, tgid, ofb->offsets[OFFSET_TGID_IN_TASK_STRUCT]);

        pi_key = ptgid;
        pi = bpf_proc_info_map_lookup_elem(&pi_key);
        if (!pi) {
            return false;
        }
    }
    struct cred *cred = (struct cred *)BPF_READ_AT(task, cred, ofb->offsets[OFFSET_CRED_IN_TASK_STRUCT]);
    kuid_t uid = BPF_READ_AT(cred, uid, ofb->offsets[OFFSET_UID_IN_CRED]);
    kgid_t gid = BPF_READ_AT(cred, gid, ofb->offsets[OFFSET_GID_IN_CRED]);
    kuid_t euid = BPF_READ_AT(cred, euid, ofb->offsets[OFFSET_EUID_IN_CRED]);
    kgid_t egid = BPF_READ_AT(cred, egid, ofb->offsets[OFFSET_EGID_IN_CRED]);

    if (pi->uid == (uint32_t) uid.value && pi->euid == (uint32_t) euid.value &&
        pi->gid == (uint32_t) gid.value && pi->egid == (uint32_t) egid.value ) {
        return false;
    }

    if (FIRST_APPLICATION_UID <= CALC_APP_ID(uid.value) &&
            FIRST_APPLICATION_UID <= CALC_APP_ID(euid.value) &&
            FIRST_APPLICATION_UID <= CALC_APP_ID(gid.value) &&
            FIRST_APPLICATION_UID <= CALC_APP_ID(egid.value)) {
        return false;
    }

    if (IS_TOP_PE_LEVEL(pi)) {
        return false;
    }
    PE_CNT_INC(pi);

    LOAD_PE_THRESHOLDS();
    bool is_over_threshold = IS_OVER_PE_THRESHOLD(pi);
    if (is_over_threshold) {
        PE_LEVEL_INC(pi);
    }
    bpf_proc_info_map_update_elem(&pi_key, pi, BPF_ANY);

#if DEBUG
    struct task_struct *real_parent = BPF_READ_AT(task, real_parent, ofb->offsets[OFFSET_REAL_PARENT_IN_TASK_STRUCT]);
    pid_t ptgid = BPF_READ_AT(real_parent, tgid, ofb->offsets[OFFSET_TGID_IN_TASK_STRUCT]);
    pid_t pid = BPF_READ_AT(task, pid, ofb->offsets[OFFSET_PID_IN_TASK_STRUCT]);

    bpf_printk("[ztd] PrivEscal.sys_enter :: Detected! - task(ptgid=%d, tgid=%d, pid=%d)", ptgid, tgid, pid);
    bpf_printk("[ztd] PrivEscal.sys_enter :: 1) uid  = %d -> %d", pi->uid, uid.value);
    bpf_printk("[ztd] PrivEscal.sys_enter :: 2) euid = %d -> %d", pi->euid, euid.value);
    bpf_printk("[ztd] PrivEscal.sys_enter :: 3) gid  = %d -> %d", pi->gid, gid.value);
    bpf_printk("[ztd] PrivEscal.sys_enter :: 4) egid = %d -> %d", pi->egid, egid.value);
#endif
    return is_over_threshold;
}

static inline __always_inline void updateProcInfo() {
    uint32_t zero = 0; // Look-up Key
    offsets_frame_buf_t *ofb = bpf_offsets_frame_map_lookup_elem(&zero);
    if (!ofb) {
        return;
    }

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (!task) {
        return;
    }
    pid_t tgid = BPF_READ_AT(task, tgid, ofb->offsets[OFFSET_TGID_IN_TASK_STRUCT]);

    struct cred *cred = (struct cred *)BPF_READ_AT(task, cred, ofb->offsets[OFFSET_CRED_IN_TASK_STRUCT]);
    kuid_t uid = BPF_READ_AT(cred, uid, ofb->offsets[OFFSET_UID_IN_CRED]);
    kgid_t gid = BPF_READ_AT(cred, gid, ofb->offsets[OFFSET_GID_IN_CRED]);
    kuid_t euid = BPF_READ_AT(cred, euid, ofb->offsets[OFFSET_EUID_IN_CRED]);
    kgid_t egid = BPF_READ_AT(cred, egid, ofb->offsets[OFFSET_EGID_IN_CRED]);

    uint32_t pi_key = tgid;
    proc_info_t pi = { (uint32_t) uid.value, (uint32_t) euid.value,
    (uint32_t) gid.value, (uint32_t) egid.value, 0, 0 };
    bpf_proc_info_map_update_elem(&pi_key, &pi, BPF_ANY);

#if DEBUG
    bpf_printk("[ztd] PrivEscal.task_rename :: Add proc_info (tgid=%d, uid=%d, euid=%d)",
                    tgid, pi.uid, pi.euid);
#endif
}

static inline __always_inline void removeProcInfo() {
    uint32_t zero = 0; // Look-up Key
    offsets_frame_buf_t *ofb = bpf_offsets_frame_map_lookup_elem(&zero);
    if (!ofb) {
        return;
    }

    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    if (!task) {
        return;
    }

    pid_t tgid = BPF_READ_AT(task, tgid, ofb->offsets[OFFSET_TGID_IN_TASK_STRUCT]);

    uint32_t pi_key = tgid;
    if (bpf_proc_info_map_lookup_elem(&pi_key) != NULL) {
        bpf_proc_info_map_delete_elem(&pi_key);
#if DEBUG
        bpf_printk("[ztd] SchedProcessExit :: Delete proc_info (tgid=%d)", tgid);
#endif
    }
}

static inline __always_inline bool isMainThread() {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = (uint32_t) (pid_tgid);
    uint32_t tgid = (uint32_t) (pid_tgid >> 32);
    return (pid == tgid) ? true : false;
}

static inline __always_inline void onTaskRename(task_rename_data_t *args) {
    if (!isMainThread()) {
        return;
    }
    char oldcomm[MAX_TASK_COMM_LEN] = {};
    bpf_probe_read_kernel_str(&oldcomm, MAX_TASK_COMM_LEN, &args->oldcomm);
    if (oldcomm[0] != 'c' ||
        oldcomm[1] != 'h' ||
        oldcomm[2] != '_' ||
        oldcomm[3] != 'z' ||
        oldcomm[4] != 'y' ||
        oldcomm[5] != 'g' ||
        oldcomm[6] != 'o' ||
        oldcomm[7] != 't' ||
        oldcomm[8] != 'e' ||
        oldcomm[9] != '\0') {
        return;
    }
    updateProcInfo();
}

static inline __always_inline void onSchedProcessExit() {
    if (!isMainThread()) {
        return;
    }
    removeProcInfo();
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_enter, priv_escal_enter)
(sys_enter_data_t *args) {
    if (isCredentialModified()) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_enter :: NR = %ld", args->id);
#endif
        onSyscallEnter(TRACE_EVENT_PRIVILEGE_ESCALATION, args);
    }
    return 1;
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_exit, priv_escal_exit)
(sys_exit_data_t *args) {
    if (isSyscallForCredChange(args->id)) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_exit :: NR = %ld", args->id);
#endif
        onSyscallExit(args->id + TRACE_EVENT_SYS_EXIT_PREFIX, args);
    } else if (isCredentialModified()) {
        onSyscallExit(TRACE_EVENT_PRIVILEGE_ESCALATION, args);
    }
    return 1;
}

DEFINE_TASK_TRACEPOINT(task_rename)
(task_rename_data_t *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] task_rename :: pid = %d, oldcomm = %s, newcomm = %s",
               args->pid, args->oldcomm, args->newcomm);
#endif
    onTaskRename(args);
    return 1;
}

DEFINE_PROC_TRACEPOINT(sched_process_exit)
(sched_process_exit_args_t *args) {
    if (DEBUG_ENTRY) {
        bpf_printk("[ztd] sched_process_exit :: comm = %s, pid = %d, prio = %d",
                   args->comm, args->pid, args->prio);
    }
    onSchedProcessExit();
    return 1;
}

LICENSE("GPL");