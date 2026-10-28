#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/printk.h>

#include "compat/kernel_compat.h"
#include "susfs.h"

#ifdef CONFIG_KSU_SUSFS
/*
 * Handle SUSFS prctl commands dispatched from hook_manager.c.
 * Only root (uid 0) can invoke SUSFS commands.
 */
int ksu_handle_susfs_prctl(int option, unsigned long arg2,
			   unsigned long arg3, unsigned long arg4,
			   unsigned long arg5)
{
	int error = 0;

	if (current_uid().val != 0)
		return 0;

#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	if (arg2 == CMD_SUSFS_ADD_SUS_PATH) {
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_sus_path))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_PATH -> arg3 not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_PATH -> arg5 not accessible\n");
			return 0;
		}
		error = susfs_add_sus_path((struct st_susfs_sus_path __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_PATH -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (arg2 == CMD_SUSFS_ADD_SUS_MOUNT) {
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_sus_mount))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> arg3 not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> arg5 not accessible\n");
			return 0;
		}
		error = susfs_add_sus_mount((struct st_susfs_sus_mount __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT) {
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_sus_kstat))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> arg3 not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> arg5 not accessible\n");
			return 0;
		}
		error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_UPDATE_SUS_KSTAT) {
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_sus_kstat))) {
			pr_err("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> arg3 not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> arg5 not accessible\n");
			return 0;
		}
		error = susfs_update_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		pr_info("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY) {
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_sus_kstat))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> arg3 not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> arg5 not accessible\n");
			return 0;
		}
		error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	if (arg2 == CMD_SUSFS_ADD_TRY_UMOUNT) {
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_try_umount))) {
			pr_err("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> arg3 not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> arg5 not accessible\n");
			return 0;
		}
		error = susfs_add_try_umount((struct st_susfs_try_umount __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS) {
		error = 0;
		susfs_try_umount(current_uid().val);
		pr_info("susfs: CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS -> ret: %d\n", error);
	}
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	if (arg2 == CMD_SUSFS_SET_UNAME) {
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_uname))) {
			pr_err("susfs: CMD_SUSFS_SET_UNAME -> arg3 not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SET_UNAME -> arg5 not accessible\n");
			return 0;
		}
		error = susfs_set_uname((struct st_susfs_uname __user *)arg3);
		pr_info("susfs: CMD_SUSFS_SET_UNAME -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	if (arg2 == CMD_SUSFS_ENABLE_LOG) {
		if (arg3 != 0 && arg3 != 1) {
			pr_err("susfs: CMD_SUSFS_ENABLE_LOG -> arg3 can only be 0 or 1\n");
			return 0;
		}
		susfs_set_log(arg3);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	if (arg2 == CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG) {
		if (!ksu_access_ok((void __user *)arg3, SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE)) {
			pr_err("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> arg3 not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> arg5 not accessible\n");
			return 0;
		}
		error = susfs_set_cmdline_or_bootconfig((char __user *)arg3);
		pr_info("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	if (arg2 == CMD_SUSFS_ADD_OPEN_REDIRECT) {
		if (!ksu_access_ok((void __user *)arg3, sizeof(struct st_susfs_open_redirect))) {
			pr_err("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> arg3 not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> arg5 not accessible\n");
			return 0;
		}
		error = susfs_add_open_redirect((struct st_susfs_open_redirect __user *)arg3);
		pr_info("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
#endif

	if (arg2 == CMD_SUSFS_SHOW_VERSION) {
		int len_of_susfs_version = strlen(SUSFS_VERSION);
		char *susfs_version = SUSFS_VERSION;
		if (!ksu_access_ok((void __user *)arg3, len_of_susfs_version + 1)) {
			pr_err("susfs: CMD_SUSFS_SHOW_VERSION -> arg3 not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SHOW_VERSION -> arg5 not accessible\n");
			return 0;
		}
		error = copy_to_user((void __user *)arg3, (void *)susfs_version, len_of_susfs_version + 1);
		pr_info("susfs: CMD_SUSFS_SHOW_VERSION -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_SHOW_ENABLED_FEATURES) {
		u64 enabled_features = 0;
		if (!ksu_access_ok((void __user *)arg3, sizeof(u64))) {
			pr_err("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> arg3 not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> arg5 not accessible\n");
			return 0;
		}
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		enabled_features |= (1ULL << 0);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		enabled_features |= (1ULL << 1);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
		enabled_features |= (1ULL << 2);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
		enabled_features |= (1ULL << 3);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
		enabled_features |= (1ULL << 4);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
		enabled_features |= (1ULL << 5);
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
		enabled_features |= (1ULL << 6);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
		enabled_features |= (1ULL << 7);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
		enabled_features |= (1ULL << 8);
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
		enabled_features |= (1ULL << 9);
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
		enabled_features |= (1ULL << 10);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
		enabled_features |= (1ULL << 11);
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		enabled_features |= (1ULL << 12);
#endif
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
		enabled_features |= (1ULL << 14);
#endif
		error = copy_to_user((void __user *)arg3, (void *)&enabled_features, sizeof(enabled_features));
		pr_info("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}
	if (arg2 == CMD_SUSFS_SHOW_VARIANT) {
		int len_of_variant = strlen(SUSFS_VARIANT);
		char *susfs_variant = SUSFS_VARIANT;
		if (!ksu_access_ok((void __user *)arg3, len_of_variant + 1)) {
			pr_err("susfs: CMD_SUSFS_SHOW_VARIANT -> arg3 not accessible\n");
			return 0;
		}
		if (!ksu_access_ok((void __user *)arg5, sizeof(error))) {
			pr_err("susfs: CMD_SUSFS_SHOW_VARIANT -> arg5 not accessible\n");
			return 0;
		}
		error = copy_to_user((void __user *)arg3, (void *)susfs_variant, len_of_variant + 1);
		pr_info("susfs: CMD_SUSFS_SHOW_VARIANT -> ret: %d\n", error);
		if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
			pr_info("susfs: copy_to_user() failed\n");
		return 0;
	}

	return 0;
}
#endif /* CONFIG_KSU_SUSFS */
