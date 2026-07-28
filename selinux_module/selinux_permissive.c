/*
 * selinux_permissive.c — 运行时 SELinux 开关 (DBY-W09)
 *
 * CONFIG_SECURITY_SELINUX_DEVELOP=n 导致 enforcing_enabled() 被编译器
 * 硬编码为 return true，所有 permissive 路径被死代码消除。
 * 本模块在运行时 patch 6 个执行点来恢复 permissive 行为。
 *
 * 支持多内核版本: 通过 UTS_VERSION 匹配 known_kernels[] 表获取偏移。
 * 添加新内核只需在表里加一条，配好 3 个"函数内偏移"即可。
 *（入口 patch 的 3 个点不需要配置，始终在 offset 0）
 *
 * 原理:
 *   1. avc_denied()               +conf.deny_off → MOV W0, WZR
 *      所有权限检查的最终裁决点。permissive 应记录日志后放行，
 *      硬编码为 return -EACCES。改返回值为 0。
 *
 *   2. security_compute_validatetrans()  入口 → MOV W0,WZR; RET
 *      exec() 时 domain 转换校验。纯校验函数无数据输出，入口 patch 最简。
 *
 *   3. security_bounded_transition()    入口 → MOV W0,WZR; RET
 *      同上，有界转换校验。
 *
 *   4. security_compute_sid()     +conf.sid_off → MOV W21, WZR
 *      compute_sid_handle_invalid_context() 内联在此。
 *      不能 patch 入口（函数需要输出 SID），只改返回值。
 *
 *   5. convert_context()         入口 → MOV W0,WZR; RET
 *      策略重载时上下文转换 (magiskpolicy --live 触发此路径)。
 *
 *   6. security_sid_mls_copy()    +conf.mls_off → MOV W22, WZR
 *      convert_context_handle_invalid_context 的第二份内联。
 *
 * 控制: /sys/kernel/selinux_permissive/selinux_permissive
 *   echo 1 → permissive     echo 0 → enforcing
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sysfs.h>
#include <linux/kallsyms.h>
#include <linux/utsname.h>

/* ── 每个内核版本的可变偏移 ─────────────────────────────────────────── */

struct kernel_config {
	const char *timestamp;      /* /proc/version 中的时间戳部分，如 "Mon Jun 24 13:57:05 CST 2024" */
	int avc_denied_off;
	int compute_sid_off;
	int sid_mls_copy_off;
};

/* 添加新内核只需加一条。用时间戳匹配，不受 #1/BP 品牌影响。 */
static struct kernel_config known_kernels[] = {
	{
		.timestamp        = "Mon Jun 24 13:57:05 CST 2024",
		.avc_denied_off   = 0x20,
		.compute_sid_off  = 0x4AC,
		.sid_mls_copy_off = 0x1AC,
	},
	{
		.timestamp        = "Fri Aug 30 08:34:06 CST 2024",
		.avc_denied_off   = 0x20,
		.compute_sid_off  = 0x4AC,
		.sid_mls_copy_off = 0x1AC,
	},
};

/* ── 指令编码 ───────────────────────────────────────────────────────── */

#define INSN_DENY   0x12800180   /* MOV W0, #0xFFFFFFF3 */
#define INSN_ALLOW  0x2A1F03E0   /* MOV W0, WZR          */
#define INSN_W21_WZR 0x2A1F03F5  /* MOV W21, WZR         */
#define INSN_W22_WZR 0x2A1F03F6  /* MOV W22, WZR         */
#define PATCH_ENTRY  { 0x2A1F03E0, 0xD65F03C0 }  /* MOV W0,WZR; RET */

/* ── Patch 点描述 ───────────────────────────────────────────────────── */

struct patch_point {
	const char *name;        /* kallsyms 符号名 */
	int insn_offset;         /* 函数入口 + offset */
	int insn_count;          /* 指令条数 */
	u32 orig[2];             /* 原始指令 */
	u32 permissive[2];       /* permissive 指令 */
};

typedef int (*patch_text_fn)(void *addrs[], u32 insns[], int cnt);

/* ── 模块状态 ───────────────────────────────────────────────────────── */

static struct kernel_config *cfg;        /* 匹配到的内核配置 */
static bool permissive;
static patch_text_fn patch_text;

/* 入口 patch（不依赖版本）用宏生成，偏移变量用函数补 */
#define ENTRY_PATCH(_sym) \
	{ .name = _sym, .insn_offset = 0, .insn_count = 2, .permissive = PATCH_ENTRY }

static struct patch_point patches[] = {
	/* [0] avc_denied — 偏移来自配置，init 时填入 */
	{ .name = "avc_denied", .insn_count = 1, .permissive = { INSN_ALLOW } },

	/* [1][2][3] 入口 patch — 偏移固定为 0 */
	ENTRY_PATCH("security_compute_validatetrans"),
	ENTRY_PATCH("security_bounded_transition"),
	/* [4] security_compute_sid — 偏移来自配置 */
	{ .name = "security_compute_sid", .insn_count = 1, .permissive = { INSN_W21_WZR } },
	ENTRY_PATCH("convert_context"),
	/* [6] security_sid_mls_copy — 偏移来自配置 */
	{ .name = "security_sid_mls_copy", .insn_count = 1, .permissive = { INSN_W22_WZR } },
};

/* ── Toggle ──────────────────────────────────────────────────────────── */

static void apply_state(bool to_permissive)
{
	void *addrs[12];
	u32 insns[12];
	int total = 0, i;

	for (i = 0; i < ARRAY_SIZE(patches) && total < 12; i++) {
		struct patch_point *p = &patches[i];
		unsigned long func = kallsyms_lookup_name(p->name);
		int j;

		if (!func) {
			pr_err("selinux_permissive: %s not found\n", p->name);
			continue;
		}

		for (j = 0; j < p->insn_count; j++) {
			addrs[total] = (void *)(func + p->insn_offset + j * 4);
			insns[total] = to_permissive ? p->permissive[j] : p->orig[j];
			total++;
		}
	}

	if (total > 0)
		patch_text(addrs, insns, total);

	permissive = to_permissive;
	pr_info("selinux_permissive: SELinux %s (%d insns)\n",
		to_permissive ? "PERMISSIVE" : "ENFORCING", total);
}

/* ── sysfs ───────────────────────────────────────────────────────────── */

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
	if (kstrtoint(buf, 10, &val) < 0) return -EINVAL;
	val = !!val;
	if (val != permissive) apply_state(val);
	return count;
}

static struct kobj_attribute permissive_attr =
	__ATTR(selinux_permissive, 0644, permissive_show, permissive_store);
static struct kobject *selinux_kobj;

/* ── 生命周期 ───────────────────────────────────────────────────────── */

static int __init selinux_permissive_init(void)
{
	const char *ver = init_utsname()->version;
	int i, ret;
	u32 *addr;

	/* 匹配内核版本 */
	for (i = 0; i < ARRAY_SIZE(known_kernels); i++) {
		if (strstr(ver, known_kernels[i].timestamp)) {
			cfg = &known_kernels[i];
			break;
		}
	}
	if (!cfg) {
		pr_err("selinux_permissive: 不支持的内核版本\n");
		pr_err("  UTS_VERSION: %s\n", ver);
		pr_err("  请在 known_kernels[] 中添加此内核的偏移配置。\n");
		return -ENODEV;
	}
	pr_info("selinux_permissive: 内核版本匹配: %s\n", cfg->timestamp);

	/* 填入版本依赖的偏移 */
	patches[0].insn_offset = cfg->avc_denied_off;       /* avc_denied */
	patches[3].insn_offset = cfg->compute_sid_off;       /* security_compute_sid */
	patches[5].insn_offset = cfg->sid_mls_copy_off;      /* security_sid_mls_copy */

	patch_text = (patch_text_fn)kallsyms_lookup_name("aarch64_insn_patch_text");
	if (!patch_text) {
		pr_err("selinux_permissive: aarch64_insn_patch_text not found\n");
		return -ENOENT;
	}

	/* 保存原始指令 */
	for (i = 0; i < ARRAY_SIZE(patches); i++) {
		struct patch_point *p = &patches[i];
		unsigned long func = kallsyms_lookup_name(p->name);
		if (!func) {
			pr_err("selinux_permissive: %s not found\n", p->name);
			return -ENOENT;
		}
		addr = (u32 *)(func + p->insn_offset);
		memcpy(p->orig, addr, p->insn_count * 4);
		pr_info("  %-38s +0x%-4x = 0x%08x\n", p->name, p->insn_offset, p->orig[0]);
	}

	selinux_kobj = kobject_create_and_add("selinux_permissive", kernel_kobj);
	if (!selinux_kobj) return -ENOMEM;
	ret = sysfs_create_file(selinux_kobj, &permissive_attr.attr);
	if (ret) { kobject_put(selinux_kobj); return ret; }

	pr_info("selinux_permissive: loaded.\n");
	pr_info("  echo 1 > /sys/kernel/selinux_permissive/selinux_permissive\n"
		"  echo 0 > /sys/kernel/selinux_permissive/selinux_permissive\n");
	return 0;
}

static void __exit selinux_permissive_exit(void)
{
	if (permissive) apply_state(false);
	sysfs_remove_file(selinux_kobj, &permissive_attr.attr);
	kobject_put(selinux_kobj);
	pr_info("selinux_permissive: unloaded.\n");
}

module_init(selinux_permissive_init);
module_exit(selinux_permissive_exit);
MODULE_LICENSE("GPL");
