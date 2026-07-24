/*
 * selinux_permissive.c - Runtime SELinux disable for DBY-W09
 *
 * Since CONFIG_SECURITY_SELINUX_DEVELOP=n, the kernel hardcodes enforcing=on.
 * This module completely bypasses SELinux without modifying kernel TEXT:
 *
 *   1. selinux_state.initialized = 0
 *      → security_compute_av(): goto allow → avd.allowed = 0xFFFFFFFF
 *      → security_compute_validatetrans/bounded_transition/sid: CBZ → return 0
 *      All NEW AVC computations allow everything.
 *
 *   2. avc_ss_reset() — flush AVC cache
 *      Old cached "deny" entries from before the toggle are evicted.
 *
 * Both are pure DATA operations — no kernel text patching needed.
 * All addresses resolved via kallsyms_lookup_name() (KASLR-safe).
 *
 * Control via sysfs:
 *   echo 1 > /sys/kernel/selinux_permissive/selinux_permissive  # disable
 *   echo 0 > /sys/kernel/selinux_permissive/selinux_permissive  # restore
 *
 * Build:
 *   source env.sh && cd dby-w09-4.0
 *   kmake M=../selinux_module modules
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kallsyms.h>

/* ── selinux_state offsets (verified from decompiled kernel) ────────── */

#define STATE_INIT_OFF   2    /* offset of 'bool initialized'    */
#define STATE_AVC_OFF    16   /* offset of 'struct selinux_avc *avc' */

/* ── Module state ────────────────────────────────────────────────────── */

static u8  *initialized_ptr;
static void *avc_ptr;          /* -> selinux_state->avc */
static u8   saved_initialized;
static bool disabled;

/* avc_ss_reset: not exported, call by address */
typedef int (*avc_ss_reset_fn)(void *avc, u32 seqno);
static avc_ss_reset_fn avc_ss_reset;

/* ── Toggle ──────────────────────────────────────────────────────────── */

static void selinux_disable(void)
{
	saved_initialized = *initialized_ptr;

	/* Disable SELinux enforcement */
	*initialized_ptr = 0;

	/* Flush AVC cache — old cached "deny" entries must be evicted */
	if (avc_ss_reset)
		avc_ss_reset(avc_ptr, 0);

	disabled = true;
	pr_info("selinux_permissive: SELinux DISABLED\n");
}

static void selinux_restore(void)
{
	/* Restore SELinux */
	*initialized_ptr = saved_initialized;

	/* Flush AVC — clear the "allow-all" entries from permissive period */
	if (avc_ss_reset)
		avc_ss_reset(avc_ptr, 0);

	disabled = false;
	pr_info("selinux_permissive: SELinux ENFORCING (restored)\n");
}

/* ── sysfs interface ─────────────────────────────────────────────────── */

static ssize_t disabled_show(struct kobject *kobj,
			     struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", disabled);
}

static ssize_t disabled_store(struct kobject *kobj,
			      struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	int val;

	if (kstrtoint(buf, 10, &val) < 0)
		return -EINVAL;

	val = !!val;
	if (val && !disabled)
		selinux_disable();
	else if (!val && disabled)
		selinux_restore();

	return count;
}

static struct kobj_attribute disabled_attr =
	__ATTR(selinux_permissive, 0644, disabled_show, disabled_store);

static struct kobject *selinux_kobj;

/* ── Module lifecycle ────────────────────────────────────────────────── */

static int __init selinux_permissive_init(void)
{
	unsigned long selinux_state_addr;
	int ret;

	/* Resolve addresses via kallsyms (KASLR-safe) */
	selinux_state_addr = kallsyms_lookup_name("selinux_state");
	if (!selinux_state_addr) {
		pr_err("selinux_permissive: selinux_state not found\n");
		return -ENOENT;
	}

	initialized_ptr = (u8 *)(selinux_state_addr + STATE_INIT_OFF);
	avc_ptr = *(void **)(selinux_state_addr + STATE_AVC_OFF);

	pr_info("selinux_permissive: selinux_state @ %px\n", (void *)selinux_state_addr);
	pr_info("selinux_permissive: initialized    @ %px = %d\n",
		initialized_ptr, *initialized_ptr);
	pr_info("selinux_permissive: avc           @ %px = %px\n",
		(void *)(selinux_state_addr + STATE_AVC_OFF), avc_ptr);

	/* Resolve avc_ss_reset (not exported to modules, call by address) */
	avc_ss_reset = (avc_ss_reset_fn)kallsyms_lookup_name("avc_ss_reset");
	if (!avc_ss_reset)
		pr_warn("selinux_permissive: avc_ss_reset not found, AVC cache won't be flushed\n");

	/* Create sysfs entry */
	selinux_kobj = kobject_create_and_add("selinux_permissive", kernel_kobj);
	if (!selinux_kobj)
		return -ENOMEM;

	ret = sysfs_create_file(selinux_kobj, &disabled_attr.attr);
	if (ret) {
		kobject_put(selinux_kobj);
		return ret;
	}

	pr_info("selinux_permissive: loaded.\n");
	pr_info("  echo 1 > /sys/kernel/selinux_permissive/selinux_permissive  # disable SELinux\n");
	pr_info("  echo 0 > /sys/kernel/selinux_permissive/selinux_permissive  # restore SELinux\n");

	return 0;
}

static void __exit selinux_permissive_exit(void)
{
	if (disabled)
		selinux_restore();

	sysfs_remove_file(selinux_kobj, &disabled_attr.attr);
	kobject_put(selinux_kobj);
	pr_info("selinux_permissive: unloaded.\n");
}

module_init(selinux_permissive_init);
module_exit(selinux_permissive_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DBY-W09 Kernel Hack");
MODULE_DESCRIPTION("Runtime SELinux disable via selinux_state without text patching");
