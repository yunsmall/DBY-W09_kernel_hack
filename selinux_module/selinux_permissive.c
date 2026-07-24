/*
 * selinux_permissive.c - Runtime SELinux permissive toggle for DBY-W09
 *
 * CONFIG_SECURITY_SELINUX_DEVELOP=n causes enforcing_enabled() to be
 * hardcoded as "return true" by the compiler.  All permissive-mode code
 * paths are dead-code-eliminated.  This module restores permissive
 * behaviour by patching five enforcement points at runtime:
 *
 *   5 enforcement points — root cause & patch for each
 *   ──────────────────────────────────────────────────
 *
 *   1. avc_denied() +0x20    → MOV W0, WZR
 *      The final "judge" in every permission check.
 *      Hook → AVC lookup → avc_denied decides grant/deny.
 *      Permissive should log+tolerate; hardcoded to return -EACCES.
 *
 *   2. security_compute_validatetrans() entry → MOV W0,WZR; RET
 *      Validates domain transitions on exec().  Returns 0 on success,
 *      -EPERM on denial.  Permissive should always allow.  Entry patch
 *      is simplest because this function only validates, no data output.
 *
 *   3. security_bounded_transition() entry → MOV W0,WZR; RET
 *      Same pattern as #2, for bounded (constrained) transitions.
 *
 *   4. security_compute_sid() +0x4AC → MOV W21, WZR
 *      The inlined compute_sid_handle_invalid_context() inside
 *      security_compute_sid().  When a computed SID is invalid,
 *      hardcoded to return -EACCES.  Cannot patch function entry
 *      because security_compute_sid() must output the computed SID.
 *      Only the "return -EACCES" instruction is patched.
 *
 *   5. convert_context() entry → MOV W0,WZR; RET
 *      Converts security contexts during policy reload
 *      (magiskpolicy --live triggers this).  Invalid conversions
 *      return -EINVAL in enforcing; patched to always return 0.
 *
 *   6. security_sid_mls_copy() +0x1AC → MOV W22, WZR
 *      Second inlined copy of convert_context_handle_invalid_context,
 *      inside security_sid_mls_copy().  Same -EINVAL pattern as #5.
 *
 *   All are patched together in a single aarch64_insn_patch_text() call
 *   (which uses stop_machine).  Every CPU sees either all-old (enforcing)
 *   or all-new (permissive) — no mixed state window.
 *   All addresses resolved via kallsyms_lookup_name() — KASLR-safe.
 *
 * Control via sysfs:
 *   echo 1 > /sys/kernel/selinux_permissive/selinux_permissive  # permissive
 *   echo 0 > /sys/kernel/selinux_permissive/selinux_permissive  # enforcing
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

/* ── Instruction encodings ───────────────────────────────────────────── */

/* avc_denied: MOV W0, #0xFFFFFFF3 → MOV W0, WZR */
#define INSN_DENY   0x12800180
#define INSN_ALLOW  0x2A1F03E0

/* Function entry: MOV W0, WZR; RET — makes function always return 0 */
#define PATCH_ENTRY_RET { 0x2A1F03E0, 0xD65F03C0 }

/* avc_denied: instruction to patch is at +0x20 from entry */
#define AVC_DENIED_INSN_OFF  0x20

/* ── Patch point descriptor ──────────────────────────────────────────── */

struct patch_point {
	const char *name;        /* function name, for kallsyms lookup */
	int insn_offset;         /* offset from function entry, 0 = patch at entry */
	int insn_count;          /* number of 32-bit instructions */
	u32 orig[2];             /* original instructions (saved on init) */
	u32 permissive[2];       /* patched instructions */
};

/* ── Module state ────────────────────────────────────────────────────── */

static bool permissive;

/*
 * aarch64_insn_patch_text — uses stop_machine() so all CPUs see the
 * transition atomically (all-old → all-new, never a mix).
 */
typedef int (*patch_text_fn)(void *addrs[], u32 insns[], int cnt);
static patch_text_fn patch_text;

/* ── Patch points ────────────────────────────────────────────────────── */

static struct patch_point patches[] = {
	{
		.name        = "avc_denied",
		.insn_offset = AVC_DENIED_INSN_OFF,  /* +0x20: MOV W0, #-13 → WZR */
		.insn_count  = 1,
		.permissive  = { INSN_ALLOW },
	},
	{
		.name        = "security_compute_validatetrans",
		.insn_offset = 0,                     /* entry → MOV W0,WZR; RET */
		.insn_count  = 2,
		.permissive  = PATCH_ENTRY_RET,
	},
	{
		.name        = "security_bounded_transition",
		.insn_offset = 0,                     /* entry → MOV W0,WZR; RET */
		.insn_count  = 2,
		.permissive  = PATCH_ENTRY_RET,
	},
	{
		.name        = "security_compute_sid",
		.insn_offset = 0x4AC,                 /* +0x4AC: MOV W21, #-13 → WZR
		                                            (compute_sid_handle_invalid_context) */
		.insn_count  = 1,
		.permissive  = { 0x2A1F03F5 },        /* MOV W21, WZR */
	},
	{
		.name        = "convert_context",
		.insn_offset = 0,                     /* entry → MOV W0,WZR; RET */
		.insn_count  = 2,
		.permissive  = PATCH_ENTRY_RET,
	},
	{
		.name        = "security_sid_mls_copy",
		.insn_offset = 0x1AC,                 /* +0x1AC: MOV W22, #-22 → WZR
		                                            (convert_context_handle_invalid_context,
		                                             2nd inlined call site) */
		.insn_count  = 1,
		.permissive  = { 0x2A1F03F6 },        /* MOV W22, WZR */
	},
};

/* ── Toggle ──────────────────────────────────────────────────────────── */

static void apply_state(bool to_permissive)
{
	/*
	 * Collect all address/instruction pairs into a single batch, then
	 * patch them all inside one stop_machine() call.  Every CPU sees
	 * either all-old (enforcing) or all-new (permissive).
	 */
	void *addrs[12];
	u32 insns[12];
	int total = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(patches) && total < 12; i++) {
		struct patch_point *p = &patches[i];
		unsigned long func = kallsyms_lookup_name(p->name);
		int j;

		if (!func) {
			pr_err("selinux_permissive: %s not found\n", p->name);
			continue;
		}

		for (j = 0; j < p->insn_count; j++) {
			addrs[total]   = (void *)(func + p->insn_offset + j * 4);
			insns[total]   = to_permissive ? p->permissive[j] : p->orig[j];
			total++;
		}
	}

	if (total > 0)
		patch_text(addrs, insns, total);

	permissive = to_permissive;
	pr_info("selinux_permissive: SELinux %s (%d insns patched)\n",
		to_permissive ? "PERMISSIVE" : "ENFORCING", total);
}

/* ── sysfs interface ─────────────────────────────────────────────────── */

static ssize_t permissive_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", permissive);
}

static ssize_t permissive_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int val;

	if (kstrtoint(buf, 10, &val) < 0)
		return -EINVAL;

	val = !!val;
	if (val != permissive)
		apply_state(val);

	return count;
}

static struct kobj_attribute permissive_attr =
	__ATTR(selinux_permissive, 0644, permissive_show, permissive_store);

static struct kobject *selinux_kobj;

/* ── Module lifecycle ────────────────────────────────────────────────── */

static int __init selinux_permissive_init(void)
{
	int i, ret;

	patch_text = (patch_text_fn)kallsyms_lookup_name("aarch64_insn_patch_text");
	if (!patch_text) {
		pr_err("selinux_permissive: aarch64_insn_patch_text not found\n");
		return -ENOENT;
	}

	/* Resolve all functions and save original instructions */
	for (i = 0; i < ARRAY_SIZE(patches); i++) {
		struct patch_point *p = &patches[i];
		unsigned long func = kallsyms_lookup_name(p->name);
		u32 *addr;

		if (!func) {
			pr_err("selinux_permissive: %s not found\n", p->name);
			return -ENOENT;
		}

		addr = (u32 *)(func + p->insn_offset);
		memcpy(p->orig, addr, p->insn_count * 4);

		pr_info("selinux_permissive: %-40s @ %px  orig=%08x%s\n",
			p->name, addr, p->orig[0],
			p->insn_count > 1 ? "..." : "");
	}

	selinux_kobj = kobject_create_and_add("selinux_permissive", kernel_kobj);
	if (!selinux_kobj)
		return -ENOMEM;

	ret = sysfs_create_file(selinux_kobj, &permissive_attr.attr);
	if (ret) {
		kobject_put(selinux_kobj);
		return ret;
	}

	pr_info("selinux_permissive: loaded (%d patch points)\n", i);
	pr_info("  echo 1 > /sys/kernel/selinux_permissive/selinux_permissive  # permissive\n");
	pr_info("  echo 0 > /sys/kernel/selinux_permissive/selinux_permissive  # enforcing\n");

	return 0;
}

static void __exit selinux_permissive_exit(void)
{
	if (permissive)
		apply_state(false);

	sysfs_remove_file(selinux_kobj, &permissive_attr.attr);
	kobject_put(selinux_kobj);
	pr_info("selinux_permissive: unloaded.\n");
}

module_init(selinux_permissive_init);
module_exit(selinux_permissive_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DBY-W09 Kernel Hack");
MODULE_DESCRIPTION("Runtime SELinux permissive toggle — 3 enforcement points patched");
