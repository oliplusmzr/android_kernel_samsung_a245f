#ifndef ZTD_PROC_SHARED_H
#define ZTD_PROC_SHARED_H

#include <sys/types.h>

#include <ztd_common.h>

#define PROG_PROC "ztdProc"

#define SCHED_PROCESS_EXEC_PROG_PATH    BPF_FS_PATH PROG_(PROG_PROC) TRACEPOINT_ "sched_sched_process_exec"
#define SCHED_PROCESS_EXIT_PROG_PATH    BPF_FS_PATH PROG_(PROG_PROC) TRACEPOINT_ "sched_sched_process_exit"
#define SCHED_PROCESS_FORK_PROG_PATH    BPF_FS_PATH PROG_(PROG_PROC) TRACEPOINT_ "sched_sched_process_fork"

#define PROC_DATA_MAP_PATH              BPF_FS_PATH MAP_(PROG_PROC)              "proc_data_map"
#define PROC_DATA_RINGBUF_PATH          BPF_FS_PATH MAP_(PROG_PROC)              "proc_data_ringbuf"
#define OFFSETS_FRAME_MAP_PATH          BPF_FS_PATH MAP_(SHARED_OBJ)             "offsets_frame_map"

#if USE_RINGBUF
# define DEFINE_PROC_TRACEPOINT(the_event) \
    DEFINE_BPF_PROG_KVER("tracepoint/sched/" #the_event, AID_ROOT, AID_SYSTEM, tp_##the_event, KVER(5, 8, 0))
#else
# define DEFINE_PROC_TRACEPOINT(the_event) \
    DEFINE_BPF_PROG("tracepoint/sched/" #the_event, AID_ROOT, AID_SYSTEM, tp_##the_event)
#endif

#define BUILD_PROC_CREATION_DATA_MAP_PATH(PROG_NAME)  BPF_FS_PATH MAP_(PROG_NAME) "proc_creation_data_map"
#define BUILD_PROC_CREATION_EVENT_NOTI_PATH(PROG_NAME) BPF_FS_PATH MAP_(PROG_NAME) "proc_creation_event_noti"
#define BUILD_SCHED_PROCESS_EXEC_PROG_PATH(PROG_NAME) BPF_FS_PATH PROG_(PROG_NAME) TRACEPOINT_ "sched_sched_process_exec"
#define BUILD_SCHED_PROCESS_EXIT_PROG_PATH(PROG_NAME) BPF_FS_PATH PROG_(PROG_NAME) TRACEPOINT_ "sched_sched_process_exit"

#define CALC_APP_ID(uid)        ((uid) % PER_USER_RANGE)
#define PER_USER_RANGE          100000
#define FIRST_APPLICATION_UID   10000
#define LAST_APPLICATION_UID    19999

typedef struct sched_process_exec_args {
    uint64_t common;
    uint32_t filename_loc;
    int32_t pid;
    int32_t old_pid;
} sched_process_exec_args_t;

typedef struct sched_process_exec_data {
    uint64_t common;                    // 8 bytes
    char filename[MAX_FP_LEN];
    int32_t pid;
    int32_t old_pid;
} sched_process_exec_data_t;

typedef struct sched_process_exit_data {
    uint64_t common;                    // 8 bytes
    char comm[MAX_TASK_COMM_LEN];
    int32_t pid;
    int32_t prio;
} sched_process_exit_data_t;

typedef struct sched_process_fork_data {
    uint64_t common;                    // 8 bytes
    char parent_comm[MAX_TASK_COMM_LEN];
    int32_t parent_pid;
    char child_comm[MAX_TASK_COMM_LEN];
    int32_t child_pid;
} sched_process_fork_data_t;

typedef struct proc_data {
    int reserve;
    int event;
    tp_base_data_t base_data;
    union {
        struct {
            sched_process_exec_data_t data;
        } sched_process_exec;
        struct {
            sched_process_exit_data_t data;
        } sched_process_exit;
        struct {
            sched_process_fork_data_t data;
        } sched_process_fork;
    } u;
} proc_data_t;

#define MAX_PE_LEVEL                5
#define MAX_PE_CNT                  0x0FFFFF
#define MAX_PE_THRESHOLDS_LEN       9 // MAX_PE_LEVEL + PAD(4)
#define IS_TOP_PE_LEVEL(pi)         (((pi)->pe_level >= MAX_PE_LEVEL) ? true : false)
#define PE_CNT_INC(pi)              ((pi)->pe_cnt < MAX_PE_CNT) ? (pi)->pe_cnt++ : ((pi)->pe_cnt = MAX_PE_CNT)
#define PE_LEVEL_INC(pi)            ((pi)->pe_level < MAX_PE_LEVEL) ? (pi)->pe_level++ : ((pi)->pe_level = MAX_PE_LEVEL)
#define GET_PE_THRESHOLD(pi)        (pe_thresholds[(pi)->pe_level])
#define IS_OVER_PE_THRESHOLD(pi)    ((pi)->pe_cnt >= GET_PE_THRESHOLD(pi))
#define LOAD_PE_THRESHOLDS()        const uint32_t pe_thresholds[MAX_PE_THRESHOLDS_LEN] = { 1, 10000, 30000, 60000, MAX_PE_CNT }

typedef struct proc_info {
    uint32_t uid;
    uint32_t euid;
    uint32_t gid;
    uint32_t egid;
    uint32_t pe_cnt:24;
    uint32_t pe_level:8;
} proc_info_t;

#endif // ZTD_PROC_SHARED_H
