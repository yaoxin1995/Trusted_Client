use std::fs;
use anyhow::{Result};


use core::str::FromStr;
use strum_macros::EnumString;

#[allow(non_camel_case_types)]
#[repr(u64)]
#[derive(Debug, Copy, Clone, PartialEq, EnumString)]
pub enum SysCallID {
    sys_read = 0 as u64,
    sys_write,
    sys_open,
    sys_close,
    sys_stat,
    sys_fstat,
    sys_lstat,
    sys_poll,
    sys_lseek,
    sys_mmap,
    sys_mprotect,
    //10
    sys_munmap,
    sys_brk,
    sys_rt_sigaction,
    sys_rt_sigprocmask,
    sys_rt_sigreturn,
    sys_ioctl,
    sys_pread64,
    sys_pwrite64,
    sys_readv,
    sys_writev,
    //20
    sys_access,
    sys_pipe,
    sys_select,
    sys_sched_yield,
    sys_mremap,
    sys_msync,
    sys_mincore,
    sys_madvise,
    sys_shmget,
    sys_shmat,
    //30
    sys_shmctl,
    sys_dup,
    sys_dup2,
    sys_pause,
    sys_nanosleep,
    sys_getitimer,
    sys_alarm,
    sys_setitimer,
    sys_getpid,
    sys_sendfile,
    //40
    sys_socket,
    sys_connect,
    sys_accept,
    sys_sendto,
    sys_recvfrom,
    sys_sendmsg,
    sys_recvmsg,
    sys_shutdown,
    sys_bind,
    sys_listen,
    //50
    sys_getsockname,
    sys_getpeername,
    sys_socketpair,
    sys_setsockopt,
    sys_getsockopt,
    sys_clone,
    sys_fork,
    sys_vfork,
    sys_execve,
    sys_exit,
    //60
    sys_wait4,
    sys_kill,
    sys_uname,
    sys_semget,
    sys_semop,
    sys_semctl,
    sys_shmdt,
    sys_msgget,
    sys_msgsnd,
    sys_msgrcv,
    //70
    sys_msgctl,
    sys_fcntl,
    sys_flock,
    sys_fsync,
    sys_fdatasync,
    sys_truncate,
    sys_ftruncate,
    sys_getdents,
    sys_getcwd,
    sys_chdir,
    //80
    sys_fchdir,
    sys_rename,
    sys_mkdir,
    sys_rmdir,
    sys_creat,
    sys_link,
    sys_unlink,
    sys_symlink,
    sys_readlink,
    sys_chmod,
    //90
    sys_fchmod,
    sys_chown,
    sys_fchown,
    sys_lchown,
    sys_umask,
    sys_gettimeofday,
    sys_getrlimit,
    sys_getrusage,
    sys_sysinfo,
    sys_times,
    //100
    sys_ptrace,
    sys_getuid,
    sys_syslog,
    sys_getgid,
    sys_setuid,
    sys_setgid,
    sys_geteuid,
    sys_getegid,
    sys_setpgid,
    sys_getppid,
    //110
    sys_getpgrp,
    sys_setsid,
    sys_setreuid,
    sys_setregid,
    sys_getgroups,
    sys_setgroups,
    sys_setresuid,
    sys_getresuid,
    sys_setresgid,
    sys_getresgid,
    //120
    sys_getpgid,
    sys_setfsuid,
    sys_setfsgid,
    sys_getsid,
    sys_capget,
    sys_capset,
    sys_rt_sigpending,
    sys_rt_sigtimedwait,
    sys_rt_sigqueueinfo,
    sys_rt_sigsuspend,
    //130
    sys_sigaltstack,
    sys_utime,
    sys_mknod,
    sys_uselib,
    sys_personality,
    sys_ustat,
    sys_statfs,
    sys_fstatfs,
    sys_sysfs,
    sys_getpriority,
    //140
    sys_setpriority,
    sys_sched_setparam,
    sys_sched_getparam,
    sys_sched_setscheduler,
    sys_sched_getscheduler,
    sys_sched_get_priority_max,
    sys_sched_get_priority_min,
    sys_sched_rr_get_interval,
    sys_mlock,
    sys_munlock,
    //150
    sys_mlockall,
    sys_munlockall,
    sys_vhangup,
    sys_modify_ldt,
    sys_pivot_root,
    sys__sysctl,
    sys_prctl,
    sys_arch_prctl,
    sys_adjtimex,
    sys_setrlimit,
    sys_chroot,
    sys_sync,
    sys_acct,
    sys_settimeofday,
    sys_mount,
    sys_umount2,
    sys_swapon,
    sys_swapoff,
    sys_reboot,
    sys_sethostname,
    //160
    sys_setdomainname,
    sys_iopl,
    sys_ioperm,
    sys_create_module,
    sys_init_module,
    sys_delete_module,
    sys_get_kernel_syms,
    sys_query_module,
    sys_quotactl,
    sys_nfsservctl,
    //180
    sys_getpmsg,
    sys_putpmsg,
    sys_afs_syscall,
    sys_tuxcall,
    sys_security,
    sys_gettid,
    sys_readahead,
    sys_setxattr,
    sys_lsetxattr,
    sys_fsetxattr,
    //190
    sys_getxattr,
    sys_lgetxattr,
    sys_fgetxattr,
    sys_listxattr,
    sys_llistxattr,
    sys_flistxattr,
    sys_removexattr,
    sys_lremovexattr,
    sys_fremovexattr,
    sys_tkill,
    //200
    sys_time,
    sys_futex,
    sys_sched_setaffinity,
    sys_sched_getaffinity,
    sys_set_thread_area,
    sys_io_setup,
    sys_io_destroy,
    sys_io_getevents,
    sys_io_submit,
    sys_io_cancel,
    //210
    sys_get_thread_area,
    sys_lookup_dcookie,
    sys_epoll_create,
    sys_epoll_ctl_old,
    sys_epoll_wait_old,
    sys_remap_file_pages,
    sys_getdents64,
    sys_set_tid_address,
    sys_restart_syscall,
    sys_semtimedop,
    //220
    sys_fadvise64,
    sys_timer_create,
    sys_timer_settime,
    sys_timer_gettime,
    sys_timer_getoverrun,
    sys_timer_delete,
    sys_clock_settime,
    sys_clock_gettime,
    sys_clock_getres,
    sys_clock_nanosleep,
    //230
    sys_exit_group,
    sys_epoll_wait,
    sys_epoll_ctl,
    sys_tgkill,
    sys_utimes,
    sys_vserver,
    sys_mbind,
    sys_set_mempolicy,
    sys_get_mempolicy,
    sys_mq_open,
    //240
    sys_mq_unlink,
    sys_mq_timedsend,
    sys_mq_timedreceive,
    sys_mq_notify,
    sys_mq_getsetattr,
    sys_kexec_load,
    sys_waitid,
    sys_add_key,
    sys_request_key,
    sys_keyctl,
    //250
    sys_ioprio_set,
    sys_ioprio_get,
    sys_inotify_init,
    sys_inotify_add_watch,
    sys_inotify_rm_watch,
    sys_migrate_pages,
    sys_openat,
    sys_mkdirat,
    sys_mknodat,
    sys_fchownat,
    //260
    sys_futimesat,
    sys_newfstatat,
    sys_unlinkat,

    sys_renameat,
    sys_linkat,
    sys_symlinkat,
    sys_readlinkat,
    sys_fchmodat,
    sys_faccessat,
    sys_pselect6,
    //270
    sys_ppoll,
    sys_unshare,
    sys_set_robust_list,
    sys_get_robust_list,
    sys_splice,
    sys_tee,
    sys_sync_file_range,
    sys_vmsplice,
    sys_move_pages,
    sys_utimensat,
    //280
    sys_epoll_pwait,
    sys_signalfd,
    sys_timerfd_create,
    sys_eventfd,
    sys_fallocate,
    sys_timerfd_settime,
    sys_timerfd_gettime,
    sys_accept4,
    sys_signalfd4,
    sys_eventfd2,
    //290
    sys_epoll_create1,
    sys_dup3,
    sys_pipe2,
    sys_inotify_init1,
    sys_preadv,
    sys_pwritev,
    sys_rt_tgsigqueueinfo,
    sys_perf_event_open,
    sys_recvmmsg,
    sys_fanotify_init,
    //300
    sys_fanotify_mark,
    sys_prlimit64,
    sys_name_to_handle_at,
    sys_open_by_handle_at,
    sys_clock_adjtime,
    sys_syncfs,
    sys_sendmmsg,
    sys_setns,
    sys_getcpu,
    sys_process_vm_readv,
    //310
    sys_process_vm_writev,
    sys_kcmp,
    sys_finit_module,
    sys_sched_setattr,
    sys_sched_getattr,
    sys_renameat2,
    sys_seccomp,
    sys_getrandom,
    sys_memfd_create,
    sys_kexec_file_load,
    //320
    sys_bpf,
    sys_stub_execveat,
    sys_userfaultfd,
    sys_membarrier,
    sys_mlock2,
    sys_copy_file_range,
    sys_preadv2,
    sys_pwritev2,
    sys_pkey_mprotect,
    sys_pkey_alloc,
    // 330
    sys_pkey_free,
    sys_statx,

    syscall_333,
    syscall_334,
    syscall_335,
    syscall_336,
    syscall_337,
    syscall_338,
    syscall_339,
    syscall_340,
    syscall_341,
    syscall_342,
    syscall_343,
    syscall_344,
    syscall_345,
    syscall_346,
    syscall_347,
    syscall_348,
    syscall_349,
    syscall_350,
    syscall_351,
    syscall_352,
    syscall_353,
    syscall_354,
    syscall_355,
    syscall_356,
    syscall_357,
    syscall_358,
    syscall_359,
    syscall_360,
    syscall_361,
    syscall_362,
    syscall_363,
    syscall_364,
    syscall_365,
    syscall_366,
    syscall_367,
    syscall_368,
    syscall_369,
    syscall_370,
    syscall_371,
    syscall_372,
    syscall_373,
    syscall_374,
    syscall_375,
    syscall_376,
    syscall_377,
    syscall_378,
    syscall_379,
    syscall_380,
    syscall_381,
    syscall_382,
    syscall_383,
    syscall_384,
    syscall_385,
    syscall_386,
    syscall_387,
    syscall_388,
    syscall_389,
    syscall_390,
    syscall_391,
    syscall_392,
    syscall_393,
    syscall_394,
    syscall_395,
    syscall_396,
    syscall_397,
    syscall_398,
    syscall_399,
    syscall_400,
    syscall_401,
    syscall_402,
    syscall_403,
    syscall_404,
    syscall_405,
    syscall_406,
    syscall_407,
    syscall_408,
    syscall_409,
    syscall_410,
    syscall_411,
    syscall_412,
    syscall_413,
    syscall_414,
    syscall_415,
    syscall_416,
    syscall_417,
    syscall_418,
    syscall_419,
    syscall_420,
    syscall_421,
    syscall_422,
    syscall_423,
    sys_pidfd_send_signal,
    sys_io_uring_setup,
    sys_io_uring_enter,
    sys_io_uring_register,
    sys_open_tree,
    sys_move_mount,
    sys_fsopen,
    sys_fsconfig,
    sys_fsmount,
    sys_fspick,
    sys_pidfd_open,
    sys_clone3,
    sys_close_range,
    sys_openat2,
    sys_pidfd_getfd,
    sys_faccessat2,
    sys_process_madvise,
    sys_epoll_pwait2,
    nt_setattr,
    sys_quotactl_fd,
    sys_landlock_create_ruleset,
    sys_landlock_add_rule,
    sys_landlock_restrict_self,
    sys_memfd_secret,
    sys_process_mrelease,
    sys_futex_waitv,
    sys_set_mempolicy_home_node,
    sys_attestation_report,
    UnknowSyscall = 452,
    sys_socket_produce = 10001,
    sys_socket_consume,
    sys_proxy,

    EXTENSION_MAX,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SingleShotCommandLineModeConfig {
    pub allowed_cmd: Vec<String>,
    pub allowed_dir: Vec<String>,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct PrivilegedUserConfig {
    pub enable_terminal: bool,
    pub enable_single_shot_command_line_mode: bool,
    pub single_shot_command_line_mode_configs : SingleShotCommandLineModeConfig,
    pub exec_result_encryption: bool,
    pub enable_container_logs_encryption:bool,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct UnprivilegedUserConfig {
    pub enable_terminal: bool,
    pub enable_single_shot_command_line_mode: bool,
    pub single_shot_command_line_mode_configs : SingleShotCommandLineModeConfig,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct EnvCmdBasedSecrets {
    pub env_variables: Vec<String>,
    pub cmd_arg: Vec<String>,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum DefaultAction {
#[warn(non_camel_case_types)]
    #[default]  
    ScmpActErrno,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
pub enum SystemCallInterceptorMode {
#[warn(non_camel_case_types)]
    #[default]  
    Global,  // the interceptor works globaly
    ContextBased, // the interceptor only works for application process
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct FrontEndSyscallInterceptorConfig {
    pub enable: bool,
    pub mode: SystemCallInterceptorMode,
    pub default_action: DefaultAction,
    pub syscalls: Vec<String>
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct BackEndSyscallInterceptorConfig {
    pub enable: bool,
    pub mode: SystemCallInterceptorMode,
    pub default_action: DefaultAction,
    pub syscalls: Vec<u64>
}

#[derive(Default, Clone, Copy, Debug, PartialOrd, Ord, Eq, PartialEq, Serialize, Deserialize)]
pub enum QkernelDebugLevel {
    #[default]
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}


#[derive(Default, Clone, Copy, Debug, PartialOrd, Ord, Eq, PartialEq, Serialize, Deserialize)]
pub struct QlogPolicy {
    pub enable: bool,
    pub allowed_max_log_level: QkernelDebugLevel
}


#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct FrontEndKbsPolicy {
    pub enable_policy_updata: bool,
    pub privileged_user_config: PrivilegedUserConfig,
    pub unprivileged_user_config:  UnprivilegedUserConfig,
    pub privileged_user_key_slice: String,
    pub qkernel_log_config: QlogPolicy,
    pub syscall_interceptor_config: FrontEndSyscallInterceptorConfig,
}


#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct BackEndKbsPolicy {
    pub enable_policy_updata: bool,
    pub privileged_user_config: PrivilegedUserConfig,
    pub unprivileged_user_config:  UnprivilegedUserConfig,
    pub privileged_user_key_slice: String,
    pub qkernel_log_config: QlogPolicy,
    pub syscall_interceptor_config: BackEndSyscallInterceptorConfig,
}



const BACKEND_POLICY_FILE_PATH: &str = "backend_policy.json";

impl FrontEndKbsPolicy {

    // if the config file exist, load file and return true; otherwise return false
    pub fn load(&mut self, policy_paht: &str) -> Result<()> {

        let contents = match fs::read_to_string(policy_paht) {
            Ok(c) => c,
            Err(e) => return Err(anyhow::Error::msg(format!("KbsPolicy Load fs::read_to_string(policy_paht) failed  error {:?}", e))),
        };

        let config = serde_json::from_str(&contents).expect("KbsPolicy Load policy wrong format");
        *self = config;
        return Ok(());
    }



    pub fn get_back_end_policy(&mut self) -> Result<BackEndKbsPolicy> {


        let allowed_syscall_number_list = self.get_allowed_syscall_number_list();


        let backend_syscall_config = BackEndSyscallInterceptorConfig {
            syscalls: allowed_syscall_number_list,
            mode: self.syscall_interceptor_config.mode.clone(),
            enable: self.syscall_interceptor_config.enable,
            default_action: self.syscall_interceptor_config.default_action.clone()
        };


        let backend_policy = BackEndKbsPolicy {
            enable_policy_updata: self.enable_policy_updata.clone(),
            privileged_user_config: self.privileged_user_config.clone(),
            unprivileged_user_config: self.unprivileged_user_config.clone(),
            privileged_user_key_slice: self.privileged_user_key_slice.clone(),
            syscall_interceptor_config : backend_syscall_config,
            qkernel_log_config: self.qkernel_log_config,
        };

        super::serialize::serialize(&backend_policy, BACKEND_POLICY_FILE_PATH).unwrap();

        Ok(backend_policy)
    }


    fn get_allowed_syscall_number_list(&self) -> Vec<u64> {
        let mut allowed_syscall_number_list = Vec::new();

        for syscall in &self.syscall_interceptor_config.syscalls {
            let syscall_id = SysCallID::from_str(syscall);

            if syscall_id.is_err() {
                continue;
            }

            allowed_syscall_number_list.push(syscall_id.unwrap() as u64);

        }
        allowed_syscall_number_list

    }
}


