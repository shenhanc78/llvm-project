  { },
//   { "tcp_eat_recv_skb", "skb_attempt_defer_free", },  // tailcall, dyn_insn_savings=43093855, size_savings=-7
//   { "tcp_send_fin", "__tcp_push_pending_frames", },  // tailcall, dyn_insn_savings=39083347, size_savings=-12
//   { "tcp_push", "__tcp_push_pending_frames", },  // tailcall, dyn_insn_savings=39082901, size_savings=-7
// //   { "check_preempt_curr", "core_tag_check_preempt_sibling", },  // tailcall, dyn_insn_savings=27913111, size_savings=-44
//   { "tick_nohz_idle_stop_tick", "nohz_balance_enter_idle", },  // tailcall, dyn_insn_savings=16611901, size_savings=-16
//   { "handle_lookup_down", "step_into", },  // tailcall, dyn_insn_savings=9548960, size_savings=-6
// //   { "getname", "getname_flags", },  // tailcall, dyn_insn_savings=4581014, size_savings=-170
//   { "mem_cgroup_stale_uncharge", "stale_record_hist", },  // tailcall, dyn_insn_savings=4013926, size_savings=0
// //   { "__smp_call_single_queue", "send_call_function_single_ipi", },  // tailcall, dyn_insn_savings=2785174, size_savings=-14
// //   { "rmap_walk_locked", "rmap_walk_anon", },  // tailcall, dyn_insn_savings=2617935, size_savings=-28
// //   { "__get_unused_fd_flags", "alloc_fd.llvm.fs_file_c", },  // tailcall, dyn_insn_savings=2417910, size_savings=-32
// //   { "vfs_open", "do_dentry_open", },  // tailcall, dyn_insn_savings=1837140, size_savings=-22
// //   { "__get_locked_pte", "pte_offset_map_lock", },  // tailcall, dyn_insn_savings=1407153, size_savings=-70
// //   { "rw_verify_area", "security_file_permission", },  // tailcall, dyn_insn_savings=1140155, size_savings=-51
//   { "walk_component", "handle_dots", },  // tailcall, dyn_insn_savings=1053078, size_savings=-6
// //   { "lru_cache_add_inactive_or_unevictable", "mlock_new_page", },  // tailcall, dyn_insn_savings=979533, size_savings=-11
// //   { "page_add_file_rmap", "mlock_page", },  // tailcall, dyn_insn_savings=510138, size_savings=-20
//   { "udpv6_queue_rcv_skb", "udpv6_queue_rcv_one_skb", },  // tailcall, dyn_insn_savings=472105, size_savings=-3
// //   { "reg_set_min_max", "reg_bounds_sync", },  // tailcall, dyn_insn_savings=407524, size_savings=-29
// //   { "__mutex_lock_interruptible_slowpath", "__mutex_lock", },  // tailcall, dyn_insn_savings=291108, size_savings=-18
// //   { "__mutex_lock_killable_slowpath", "__mutex_lock", },  // tailcall, dyn_insn_savings=291108, size_savings=-18
// //   { "pid_update_inode", "security_task_to_inode", },  // tailcall, dyn_insn_savings=229528, size_savings=-25
// //   { "ksys_mmap_pgoff", "vm_mmap_pgoff", },  // tailcall, dyn_insn_savings=199093, size_savings=-38
//   { "free_htab_elem", "__pcpu_freelist_push", },  // tailcall, dyn_insn_savings=190084, size_savings=-6
// //   { "security_vm_enough_memory_mm", "__vm_enough_memory", },  // tailcall, dyn_insn_savings=181374, size_savings=-44
// //   { "udp_queue_rcv_skb", "udp_queue_rcv_one_skb", },  // tailcall, dyn_insn_savings=157283, size_savings=-5
//   { "quiet_vmstat", "refresh_cpu_vm_stats", },  // tailcall, dyn_insn_savings=146238, size_savings=-13
// //   { "page_remove_rmap", "munlock_page", },  // tailcall, dyn_insn_savings=141727, size_savings=-21
// //   { "check_func_arg_reg_off", "__check_ptr_off_reg", },  // tailcall, dyn_insn_savings=130176, size_savings=-24
// //   { "__radix_tree_delete", "delete_node", },  // tailcall, dyn_insn_savings=89418, size_savings=-20
// //   { "__radix_tree_replace", "delete_node", },  // tailcall, dyn_insn_savings=89418, size_savings=-29
// //   { "__radix_tree_replace", "delete_node", },  // tailcall, dyn_insn_savings=89418, size_savings=-29
// //   { "radix_tree_iter_replace", "__radix_tree_replace", "delete_node", },  // tailcall, dyn_insn_savings=89418, size_savings=-29
// //   { "radix_tree_iter_replace", "__radix_tree_replace", "delete_node", },  // tailcall, dyn_insn_savings=89418, size_savings=-29
// //   { "ext4_ext_tree_init", "__ext4_mark_inode_dirty", },  // tailcall, dyn_insn_savings=88470, size_savings=-124
//   { "phys_mem_access_encrypted", "arch_memremap_can_ram_remap", },  // tailcall, dyn_insn_savings=75482, size_savings=-7
// //   { "bfq_bfqq_charge_time", "bfq_bfqq_served", },  // tailcall, dyn_insn_savings=71412, size_savings=-8
// //   { "check_mem_size_reg", "__mark_chain_precision", },  // tailcall, dyn_insn_savings=70623, size_savings=-44
// //   { "exit_files", "put_files_struct", },  // tailcall, dyn_insn_savings=68013, size_savings=-15
// //   { "___pud_free_tlb", "tlb_flush_mmu", },  // tailcall, dyn_insn_savings=64578, size_savings=-32
// //   { "clear_caller_saved_regs", "check_reg_arg", },  // tailcall, dyn_insn_savings=60611, size_savings=-81
// //   { "relock_page_lruvec_irq", "lock_page_lruvec_irq", },  // tailcall, dyn_insn_savings=51904, size_savings=-15
// //   { "relock_page_lruvec_irq", "lock_page_lruvec_irq", },  // tailcall, dyn_insn_savings=51904, size_savings=-15
// //   { "proc_flush_pid", "proc_invalidate_siblings_dcache", },  // tailcall, dyn_insn_savings=51694, size_savings=-13
// //   { "__blk_queue_split", "blk_throtl_charge_bio_split", },  // tailcall, dyn_insn_savings=49888, size_savings=-10
// //   { "bfq_weights_tree_remove", "bfq_put_queue", },  // tailcall, dyn_insn_savings=49768, size_savings=-65
// //   { "tty_buffer_flush_work", "__flush_work.llvm.kernel_workqueue_c", },  // tailcall, dyn_insn_savings=49234, size_savings=-89
//   { "lru_note_cost_page", "lru_note_cost", },  // tailcall, dyn_insn_savings=48972, size_savings=-3
// //   { "bpf_map_new_fd", "__anon_inode_getfd.llvm.fs_anon_inodes_c", },  // tailcall, dyn_insn_savings=48499, size_savings=-54
// //   { "bpf_prog_new_fd", "__anon_inode_getfd.llvm.fs_anon_inodes_c", },  // tailcall, dyn_insn_savings=48371, size_savings=-55
// //   { "__blk_mq_free_request", "blk_queue_exit", },  // tailcall, dyn_insn_savings=48178, size_savings=-29
// //   { "__blk_mq_alloc_request", "blk_mq_rq_ctx_init", },  // tailcall, dyn_insn_savings=48174, size_savings=-12
// //   { "bpf_link_new_fd", "__anon_inode_getfd.llvm.fs_anon_inodes_c", },  // tailcall, dyn_insn_savings=48161, size_savings=-52
// //   { "bfq_bfqq_move", "bfq_put_queue", },  // tailcall, dyn_insn_savings=47900, size_savings=-67
// //   { "bfq_release_process_ref", "bfq_put_queue", },  // tailcall, dyn_insn_savings=47705, size_savings=-76
// //   { "__bfq_weights_tree_remove", "bfq_put_queue", },  // tailcall, dyn_insn_savings=47684, size_savings=-66
// //   { "bfq_put_idle_entity", "bfq_put_queue", },  // tailcall, dyn_insn_savings=47684, size_savings=-66
// //   { "scsi_finish_command", "scsi_io_completion", },  // tailcall, dyn_insn_savings=47594, size_savings=-6
// //   { "ext4_da_update_reserve_space", "ext4_discard_preallocations", },  // tailcall, dyn_insn_savings=46366, size_savings=-18
// //   { "ldsem_up_read", "ldsem_wake", },  // tailcall, dyn_insn_savings=45210, size_savings=-66
// //   { "ldsem_up_write", "ldsem_wake", },  // tailcall, dyn_insn_savings=45210, size_savings=-23
// //   { "tty_ldisc_unlock", "ldsem_up_write", "ldsem_wake", },  // tailcall, dyn_insn_savings=45210, size_savings=-33
// //   { "ext4_handle_dirty_dirblock", "__ext4_handle_dirty_metadata", },  // tailcall, dyn_insn_savings=40315, size_savings=-80
// //   { "__ptrace_may_access", "security_ptrace_access_check", },  // tailcall, dyn_insn_savings=39116, size_savings=-8
// //   { "stop_one_cpu_nowait", "cpu_stop_queue_work", },  // tailcall, dyn_insn_savings=38430, size_savings=-17
// //   { "bfq_setup_cooperator", "bfq_setup_merge", },  // tailcall, dyn_insn_savings=38010, size_savings=-12
// //   { "skcipher_walk_skcipher", "skcipher_walk_next", },  // tailcall, dyn_insn_savings=36625, size_savings=-18
// //   { "ext4_handle_dirty_dx_node", "__ext4_handle_dirty_metadata", },  // tailcall, dyn_insn_savings=33450, size_savings=-69
// //   { "ext4_read_bh_nowait", "submit_bh_wbc.llvm.fs_buffer_c", },  // tailcall, dyn_insn_savings=32155, size_savings=-53
// //   { "detach_task_cfs_rq", "detach_entity_cfs_rq", },  // tailcall, dyn_insn_savings=27808, size_savings=-15
// //   { "detach_task_cfs_rq", "detach_entity_cfs_rq", },  // tailcall, dyn_insn_savings=27808, size_savings=-15
// //   { "detach_task_cfs_rq", "detach_entity_cfs_rq", },  // tailcall, dyn_insn_savings=27808, size_savings=-15
// //   { "asi_post_flush_tlb_global", "asi_set_context_tlb_gens", },  // tailcall, dyn_insn_savings=24442, size_savings=-17
// //   { "exit_swg", "do_gsys_swg_leave.llvm.kernel_sched_core_c", },  // tailcall, dyn_insn_savings=23642, size_savings=-12
// //   { "detach_pid", "free_pid", },  // tailcall, dyn_insn_savings=22164, size_savings=-30
//   { "show_sb_opts", "security_sb_show_options", },  // tailcall, dyn_insn_savings=19194, size_savings=-8
// //   { "split_vma", "__split_vma", },  // tailcall, dyn_insn_savings=16053, size_savings=-30
//   { "ext4_wait_block_bitmap", "ext4_validate_block_bitmap", },  // tailcall, dyn_insn_savings=15880, size_savings=-6
//   { "dequeue_rt_stack", "dequeue_top_rt_rq", },  // tailcall, dyn_insn_savings=15631, size_savings=-7
// //   { "verity_hash_init", "verity_hash_update", },  // tailcall, dyn_insn_savings=15101, size_savings=-10
// //   { "page_add_anon_rmap", "do_page_add_anon_rmap", },  // tailcall, dyn_insn_savings=13297, size_savings=-12
// //   { "tty_buffer_cancel_work", "__cancel_work_timer.llvm.kernel_workqueue_c", },  // tailcall, dyn_insn_savings=13098, size_savings=-29
// //   { "sysfs_delete_link", "kernfs_remove_by_name_ns", },  // tailcall, dyn_insn_savings=12729, size_savings=-194
//   { "pcpu_block_update_hint_alloc", "pcpu_chunk_refresh_hint", },  // tailcall, dyn_insn_savings=12504, size_savings=1
// //   { "__kfence_free", "kfence_guarded_free", },  // tailcall, dyn_insn_savings=12462, size_savings=-12
// //   { "access_remote_vm", "__access_remote_vm", },  // tailcall, dyn_insn_savings=12320, size_savings=-24
// //   { "inotify_ignored_and_remove_idr", "dec_ucount", },  // tailcall, dyn_insn_savings=8044, size_savings=-60
// //   { "bfq_requeue_bfqq", "bfq_activate_requeue_entity", },  // tailcall, dyn_insn_savings=7685, size_savings=-16
// //   { "attach_tasks", "raw_spin_rq_unlock", },  // tailcall, dyn_insn_savings=7526, size_savings=-156
// //   { "ext4_fc_track_unlink", "__ext4_fc_track_unlink", },  // tailcall, dyn_insn_savings=7260, size_savings=-12
// //   { "seccomp_filter_release", "__seccomp_filter_release", },  // tailcall, dyn_insn_savings=6864, size_savings=-13
//   { "_install_special_mapping", "__install_special_mapping.llvm.mm_mmap_c", },  // tailcall, dyn_insn_savings=6372, size_savings=-6
// //   { "ksys_dup3", "do_dup2", },  // tailcall, dyn_insn_savings=6312, size_savings=-15
// //   { "expand_stack", "expand_downwards", },  // tailcall, dyn_insn_savings=5923, size_savings=-7
// //   { "ext4_fc_track_create", "__ext4_fc_track_create", },  // tailcall, dyn_insn_savings=4512, size_savings=-15
// //   { "__group_send_sig_info", "send_signal.llvm.kernel_signal_c", "__send_signal", },  // tailcall, dyn_insn_savings=4506, size_savings=-30
// //   { "exec_mm_release", "mm_release.llvm.kernel_fork_c", },  // tailcall, dyn_insn_savings=4490, size_savings=-14
// //   { "exit_mm_release", "mm_release.llvm.kernel_fork_c", },  // tailcall, dyn_insn_savings=4490, size_savings=-14
//   { "fscrypt_set_per_file_enc_key", "fscrypt_prepare_key", },  // tailcall, dyn_insn_savings=4147, size_savings=-3
// //   { "kobject_add_varg", "kobject_add_internal", },  // tailcall, dyn_insn_savings=4088, size_savings=-11
//   { "watchdog_buddy_check_hardlockup", "watchdog_hardlockup_check", },  // tailcall, dyn_insn_savings=3888, size_savings=-6
// //   { "ext4_read_bh_lock", "ext4_read_bh", },  // tailcall, dyn_insn_savings=3658, size_savings=-34
//   { "split_huge_pmd_address", "__split_huge_pmd", },  // tailcall, dyn_insn_savings=3151, size_savings=-7
// //   { "ext4_alloc_da_blocks", "__filemap_fdatawrite_range", },  // tailcall, dyn_insn_savings=2193, size_savings=-46
// //   { "mark_wake_futex", "wake_q_add_safe", },  // tailcall, dyn_insn_savings=2165, size_savings=-18
// //   { "asi_map", "__asi_map_gfp", },  // tailcall, dyn_insn_savings=2016, size_savings=-22
// //   { "complete_signal", "add_task_to_pi_list", },  // tailcall, dyn_insn_savings=2005, size_savings=-17
// //   { "arch_randomize_brk", "randomize_page", },  // tailcall, dyn_insn_savings=1594, size_savings=-11
// //   { "ext4_sb_bread", "__ext4_sb_bread_gfp.llvm.fs_ext4_super_c", },  // tailcall, dyn_insn_savings=1427, size_savings=-41
// //   { "attach_one_task", "raw_spin_rq_unlock", },  // tailcall, dyn_insn_savings=1192, size_savings=-146
// //   { "static_key_slow_dec_cpuslocked", "__static_key_slow_dec_cpuslocked", },  // tailcall, dyn_insn_savings=1101, size_savings=-43
// //   { "static_key_slow_dec_cpuslocked", "__static_key_slow_dec_cpuslocked", },  // tailcall, dyn_insn_savings=1101, size_savings=-43
// //   { "__bfq_bfqq_expire", "__bfq_bfqd_reset_in_service", },  // tailcall, dyn_insn_savings=1073, size_savings=-6
// //   { "__secure_computing", "__seccomp_filter", },  // tailcall, dyn_insn_savings=989, size_savings=-6
// //   { "blk_mq_queue_tag_busy_iter", "blk_queue_exit", },  // tailcall, dyn_insn_savings=938, size_savings=-39
// //   { "signal_wake_up_state", "add_task_to_pi_list", },  // tailcall, dyn_insn_savings=847, size_savings=-52
// //   { "do_add_mount", "graft_tree", "attach_recursive_mnt", },  // tailcall, dyn_insn_savings=843, size_savings=-13
// //   { "device_pm_remove", "device_pm_check_callbacks", },  // tailcall, dyn_insn_savings=744, size_savings=-25
// //   { "blk_flush_complete_seq", "blk_mq_add_to_requeue_list", },  // tailcall, dyn_insn_savings=720, size_savings=-9
// //   { "mem_cgroup_flush_stats", "cgroup_rstat_flush", },  // tailcall, dyn_insn_savings=643, size_savings=-59
// //   { "mem_cgroup_flush_stats_ratelimited", "mem_cgroup_flush_stats", "cgroup_rstat_flush", },  // tailcall, dyn_insn_savings=643, size_savings=-68
// //   { "drop_collected_mounts", "namespace_unlock", },  // tailcall, dyn_insn_savings=605, size_savings=-48
// //   { "lru_gen_migrate_mm", "lru_gen_add_mm", },  // tailcall, dyn_insn_savings=567, size_savings=-15
// //   { "audit_signal_info", "audit_signal_info_syscall", },  // tailcall, dyn_insn_savings=474, size_savings=-6
// //   { "check_kill_permission", "security_task_kill", },  // tailcall, dyn_insn_savings=436, size_savings=-7
// //   { "devres_release_all", "release_nodes", },  // tailcall, dyn_insn_savings=396, size_savings=-13
// //   { "tcp_event_new_data_sent", "tcp_check_space", },  // tailcall, dyn_insn_savings=327, size_savings=-21
// //   { "css_clear_dir", "cgroup_addrm_files", },  // tailcall, dyn_insn_savings=278, size_savings=-25
// //   { "exit_io_context", "put_io_context", },  // tailcall, dyn_insn_savings=272, size_savings=-14
// //   { "tcp_push_one", "tcp_write_xmit", },  // tailcall, dyn_insn_savings=236, size_savings=-9
// //   { "device_initial_probe", "__device_attach.llvm.drivers_base_dd_c", },  // tailcall, dyn_insn_savings=216, size_savings=-13
// //   { "tcp_send_loss_probe", "tcp_rearm_rto", },  // tailcall, dyn_insn_savings=189, size_savings=-30
// //   { "lru_add_drain_all", "__lru_add_drain_all", },  // tailcall, dyn_insn_savings=186, size_savings=-43
// //   { "bpf_prog_kallsyms_add", "bpf_ksym_add", },  // tailcall, dyn_insn_savings=172, size_savings=-14
// //   { "bfq_put_async_queues", "__bfq_put_async_bfqq", },  // tailcall, dyn_insn_savings=170, size_savings=-35
// //   { "scan_children", "scan_inflight", },  // tailcall, dyn_insn_savings=144, size_savings=0
// //   { "sysfs_remove_dir", "kernfs_remove", },  // tailcall, dyn_insn_savings=135, size_savings=-42
// //   { "lru_add_drain", "mlock_page_drain_local", },  // tailcall, dyn_insn_savings=114, size_savings=-87
// //   { "partition_sched_domains_locked", "register_sched_domain_sysctl", },  // tailcall, dyn_insn_savings=96, size_savings=-1
// //   { "jump_label_update", "__jump_label_update", "arch_jump_label_transform_apply", },  // tailcall, dyn_insn_savings=90, size_savings=-25
// //   { "bpf_obj_pin", "bpf_obj_pin_user", },  // tailcall, dyn_insn_savings=77, size_savings=-3
// //   { "bpf_jit_alloc_exec", "module_alloc", },  // tailcall, dyn_insn_savings=73, size_savings=-21
// //   { "__bad_area_nosemaphore", "no_context", },  // tailcall, dyn_insn_savings=72, size_savings=-1
// //   { "__jump_label_update", "arch_jump_label_transform_apply", },  // tailcall, dyn_insn_savings=72, size_savings=-7
// //   { "bad_area_nosemaphore", "__bad_area_nosemaphore", "no_context", },  // tailcall, dyn_insn_savings=72, size_savings=-11
// //   { "bpf_prog_get", "__bpf_prog_get", },  // tailcall, dyn_insn_savings=69, size_savings=-36
// //   { "bpf_prog_kallsyms_del_all", "bpf_ksym_del", },  // tailcall, dyn_insn_savings=60, size_savings=-25
// //   { "update_cpumasks_hier", "rebuild_sched_domains_locked", },  // tailcall, dyn_insn_savings=58, size_savings=-18
// //   { "pci_power_up", "pci_raw_set_power_state", },  // tailcall, dyn_insn_savings=56, size_savings=-22
// //   { "invalidate_mapping_pagevec", "__invalidate_mapping_pages", },  // tailcall, dyn_insn_savings=55, size_savings=-12
// //   { "attribute_container_add_class_device", "attribute_container_add_attrs", },  // tailcall, dyn_insn_savings=54, size_savings=-13
// //   { "__get_filter", "bpf_prepare_filter", },  // tailcall, dyn_insn_savings=39, size_savings=-7
// //   { "__dm_destroy", "free_dev", },  // tailcall, dyn_insn_savings=36, size_savings=-9
// //   { "dm_destroy", "__dm_destroy", "free_dev", },  // tailcall, dyn_insn_savings=36, size_savings=-14
// //   { "pm_runtime_put_suppliers", "device_links_read_unlock", },  // tailcall, dyn_insn_savings=30, size_savings=-22
// //   { "rdtgroup_kn_unlock", "rdtgroup_kn_put", "kernfs_unbreak_active_protection", },  // tailcall, dyn_insn_savings=30, size_savings=-49
// //   { "pm_runtime_get_suppliers", "device_links_read_unlock", },  // tailcall, dyn_insn_savings=24, size_savings=-23
// //   { "prctl_set_seccomp", "do_seccomp", },  // tailcall, dyn_insn_savings=24, size_savings=-14
// //   { "blk_mq_free_rq_map", "blk_mq_free_tags", },  // tailcall, dyn_insn_savings=18, size_savings=-10
// //   { "fort_gox_free_superblock", "free_sb", },  // tailcall, dyn_insn_savings=18, size_savings=-17
// //   { "queue_if_no_path", "process_queued_io_list", },  // tailcall, dyn_insn_savings=16, size_savings=-21
// //   { "tcp_non_congestion_loss_retransmit", "tcp_xmit_retransmit_queue", },  // tailcall, dyn_insn_savings=15, size_savings=-13
// //   { "pci_restore_standard_config", "pci_pme_restore", },  // tailcall, dyn_insn_savings=14, size_savings=-12
// //   { "cpupri_find", "cpupri_find_fitness", },  // tailcall, dyn_insn_savings=12, size_savings=-8
// //   { "__kmem_cache_shutdown", "__kmem_cache_shrink", },  // tailcall, dyn_insn_savings=8, size_savings=-13
// //   { "blk_mq_release", "blk_mq_sysfs_deinit", },  // tailcall, dyn_insn_savings=8, size_savings=-6
// //   { "bpf_btf_get_fd_by_id", "btf_get_fd_by_id", },  // tailcall, dyn_insn_savings=7, size_savings=-5
// //   { "htab_free_elems", "bpf_map_area_free", },  // tailcall, dyn_insn_savings=6, size_savings=-48
// //   { "rdtgroup_kn_put", "kernfs_unbreak_active_protection", },  // tailcall, dyn_insn_savings=6, size_savings=-29
// //   { "setup_cpu_cache", "enable_cpucache", },  // tailcall, dyn_insn_savings=6, size_savings=-5
// //   { "arch_seccomp_spec_mitigate", "ib_prctl_set", },  // tailcall, dyn_insn_savings=4, size_savings=-15
// //   { "__dev_pm_qos_resume_latency", "pm_qos_read_value", },  // tailcall, dyn_insn_savings=0, size_savings=-26
// //   { "__receive_sock", "cgroup_net_set_sock_classid", },  // tailcall, dyn_insn_savings=0, size_savings=-10
// //   { "attach_mnt", "__attach_mnt", },  // tailcall, dyn_insn_savings=0, size_savings=-19
// //   { "bfq_activate_bfqq", "bfq_clear_bfqq_non_blocking_wait_rq", },  // tailcall, dyn_insn_savings=0, size_savings=-12
// //   { "blkcg_exit_queue", "blk_throtl_exit", },  // tailcall, dyn_insn_savings=0, size_savings=-9
// //   { "bpf_jit_free_exec", "module_memfree", },  // tailcall, dyn_insn_savings=0, size_savings=-47
// //   { "bpf_map_area_mmapable_alloc", "__bpf_map_area_alloc", },  // tailcall, dyn_insn_savings=0, size_savings=-10
// //   { "cleanup_mapped_device", "dm_mq_cleanup_mapped_device", },  // tailcall, dyn_insn_savings=0, size_savings=-8
// //   { "exit_task_namespaces", "free_nsproxy", },  // tailcall, dyn_insn_savings=0, size_savings=-17
// //   { "exit_thread", "fpu__drop", },  // tailcall, dyn_insn_savings=0, size_savings=-12
// //   { "invalidate_inode_page", "remove_mapping", },  // tailcall, dyn_insn_savings=0, size_savings=-18
// //   { "kernfs_drain_open_files", "kernfs_put_open_node", },  // tailcall, dyn_insn_savings=0, size_savings=-9
// //   { "lruvec_init", "lru_gen_init_lruvec", },  // tailcall, dyn_insn_savings=0, size_savings=-11
// //   { "mem_cgroup_stale_charge", "test_and_visit_page", },  // tailcall, dyn_insn_savings=0, size_savings=-9
// //   { "orc_find", "arch_orc_find", },  // tailcall, dyn_insn_savings=0, size_savings=-12
// //   { "post_init_entity_util_avg", "attach_entity_cfs_rq", },  // tailcall, dyn_insn_savings=0, size_savings=-20
// //   { "prealloc_destroy", "pcpu_freelist_destroy", },  // tailcall, dyn_insn_savings=0, size_savings=-13
// //   { "propagate_one", "count_mounts", },  // tailcall, dyn_insn_savings=0, size_savings=-8
// //   { "psp_reuseport_free", "psp_listen_hash_put", },  // tailcall, dyn_insn_savings=0, size_savings=-12
// //   { "schedule_tail", "calculate_sigpending", },  // tailcall, dyn_insn_savings=0, size_savings=-1
// //   { "security_inode_setxattr", "cap_inode_setxattr", },  // tailcall, dyn_insn_savings=0, size_savings=-4
// //   { "sk_filter_uncharge", "sk_filter_release", },  // tailcall, dyn_insn_savings=0, size_savings=-23
// //   { "try_grab_compound_head", "try_get_compound_head", },  // tailcall, dyn_insn_savings=0, size_savings=-11
// //   { "wb_domain_init", "fprop_global_init", },  // tailcall, dyn_insn_savings=0, size_savings=-13
// //   { "evict", "destroy_inode", },  // tailcall, dyn_insn_savings=-4021513, size_savings=-21
// //   { "string", "widen_string", },  // tailcall, dyn_insn_savings=-4193166, size_savings=-44
// //   { "string", "widen_string", },  // tailcall, dyn_insn_savings=-4193166, size_savings=-44
// //   { "page_to_pgoff", "hugetlb_basepage_index", },  // tailcall, dyn_insn_savings=-5866136, size_savings=-39
// //   { "rmap_walk", "rmap_walk_anon", },  // tailcall, dyn_insn_savings=-6031445, size_savings=-35
// //   { "__fsnotify_vfsmount_delete", "fsnotify_destroy_marks", },  // tailcall, dyn_insn_savings=-6282089, size_savings=-37
// //   { "rmap_walk", "rmap_walk_file", },  // tailcall, dyn_insn_savings=-7267172, size_savings=-35
// //   { "put_dec", "put_dec_trunc8", },  // tailcall, dyn_insn_savings=-9692044, size_savings=-16
// //   { "update_process_times", "run_posix_cpu_timers", },  // tailcall, dyn_insn_savings=-11704878, size_savings=-14
// //   { "rwsem_mark_wake", "wake_q_add", },  // tailcall, dyn_insn_savings=-12864813, size_savings=-51
// //   { "drain_array_locked", "memmove", },  // tailcall, dyn_insn_savings=-25070016, size_savings=-197
// //   { "hrtimer_force_reprogram", "clockevents_program_event", },  // tailcall, dyn_insn_savings=-26040733, size_savings=-51
// //   { "tick_program_event", "clockevents_program_event", },  // tailcall, dyn_insn_savings=-63191656, size_savings=-68
// //   { "nohz_run_idle_balance", "_nohz_idle_balance", },  // tailcall, dyn_insn_savings=-73567238, size_savings=-4
// //   { "common_interrupt", "__asi_enter", },  // tailcall, dyn_insn_savings=-83992396, size_savings=-162
// //   { "exc_int3", "__asi_enter", },  // tailcall, dyn_insn_savings=-83992396, size_savings=-166
// //   { "exc_page_fault", "__asi_enter", },  // tailcall, dyn_insn_savings=-83992396, size_savings=-165
// //   { "sysvec_apic_timer_interrupt", "__asi_enter", },  // tailcall, dyn_insn_savings=-83992396, size_savings=-166
// //   { "sysvec_call_function", "__asi_enter", },  // tailcall, dyn_insn_savings=-83992396, size_savings=-166
// //   { "sysvec_call_function_single", "__asi_enter", },  // tailcall, dyn_insn_savings=-83992396, size_savings=-166
// //   { "sysvec_reschedule_ipi", "__asi_enter", },  // tailcall, dyn_insn_savings=-83992396, size_savings=-166
// //   { "sk_forced_mem_schedule", "mem_cgroup_charge_skmem", },  // tailcall, dyn_insn_savings=-127798739, size_savings=-48
// //   { "tick_nohz_idle_retain_tick", "timer_clear_idle", },  // tailcall, dyn_insn_savings=-137520096, size_savings=-34
// //   { "set_cpus_allowed_ptr_flags", "__set_cpus_allowed_ptr.llvm.kernel_sched_core_c", },  // tailcall, dyn_insn_savings=-158021650, size_savings=-57
// //   { "update_wall_time", "timekeeping_advance.llvm.kernel_time_timekeeping_c", },  // tailcall, dyn_insn_savings=-165910389, size_savings=-47
// //   { "do_timer", "calc_global_load", },  // tailcall, dyn_insn_savings=-166778591, size_savings=-48
// //   { "set_current_blocked", "__set_current_blocked", },  // tailcall, dyn_insn_savings=-208618498, size_savings=-82
// //   { "__irq_exit_rcu", "tick_nohz_irq_exit", },  // tailcall, dyn_insn_savings=-211413569, size_savings=-13
// //   { "destroy_worker", "__try_to_wake_up.llvm.kernel_sched_core_c", },  // tailcall, dyn_insn_savings=-252642214, size_savings=-289
// //   { "insert_work", "__try_to_wake_up.llvm.kernel_sched_core_c", },  // tailcall, dyn_insn_savings=-252642214, size_savings=-284
// //   { "wake_up_state", "__try_to_wake_up.llvm.kernel_sched_core_c", },  // tailcall, dyn_insn_savings=-252642214, size_savings=-309
// //   { "wake_up_state_exiting", "__try_to_wake_up.llvm.kernel_sched_core_c", },  // tailcall, dyn_insn_savings=-252642214, size_savings=-280
// //   { "__stun_sibling", "send_sibling_stun_ipi", },  // tailcall, dyn_insn_savings=-296527111, size_savings=-84
// //   { "irq_exit_rcu", "tick_nohz_irq_exit", },  // tailcall, dyn_insn_savings=-309835845, size_savings=-74
// //   { "__mutex_lock_slowpath", "__mutex_lock", },  // tailcall, dyn_insn_savings=-500039712, size_savings=-26
// //   { "rcu_irq_enter", "rcu_nmi_enter", },  // tailcall, dyn_insn_savings=-504734268, size_savings=-33
// //   { "rcu_irq_exit", "rcu_nmi_exit", },  // tailcall, dyn_insn_savings=-525207454, size_savings=-40
// //   { "rcu_eqs_enter", "rcu_dynticks_eqs_enter", },  // tailcall, dyn_insn_savings=-563601098, size_savings=-23
// //   { "event_sched_out", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6225742912, size_savings=-30714
// //   { "unlink1", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226278750, size_savings=-30703
// //   { "__blk_mq_sched_bio_merge", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226330488, size_savings=-30703
// //   { "elv_merge", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226330488, size_savings=-30704
// //   { "__do_set_cpus_allowed.llvm.kernel_sched_core_c", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226368686, size_savings=-30718
// //   { "do_set_cpus_allowed", "__do_set_cpus_allowed.llvm.kernel_sched_core_c", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226368686, size_savings=-30724
// //   { "fsnotify_destroy_event", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226369320, size_savings=-30719
// //   { "blk_mq_update_queue_map", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377496, size_savings=-30702
// //   { "nonced_checksum_init_request", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377496, size_savings=-30705
// //   { "bpf_link_free", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377508, size_savings=-30708
// //   { "klist_put", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377508, size_savings=-30705
// //   { "security_setprocattr", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377514, size_savings=-30702
// //   { "__ata_qc_complete", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30709
// //   { "cgroup_procs_write_finish", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30705
// //   { "deferrable_resched_curr", "resched_curr", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30858
// //   { "deferrable_resched_curr", "resched_curr", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30858
// //   { "deferrable_resched_curr", "resched_curr", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30858
// //   { "deferrable_resched_curr", "resched_curr", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30858
// //   { "deferrable_resched_curr", "resched_curr", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30858
// //   { "deferrable_resched_curr", "resched_curr", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30858
// //   { "elv_former_request", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30709
// //   { "elv_latter_request", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30709
// //   { "fscrypt_policy_to_inherit", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30715
// //   { "fsnotify_handle_inode_event", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30704
// //   { "ghost_bpf_prog_free", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30709
// //   { "kobj_ns_ops", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30706
// //   { "kobject_get_ownership", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30730
// //   { "parse_monolithic_mount_data", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30720
// //   { "resched_cpu_unlocked", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30747
// //   { "sched_change_group", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30706
// //   { "tcp_mark_skb_lost", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30721
// //   { "zpool_freeable", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30710
// //   { "zpool_get_total_size", "__x86_indirect_thunk_r11", },  // tailcall, dyn_insn_savings=-6226377520, size_savings=-30713
