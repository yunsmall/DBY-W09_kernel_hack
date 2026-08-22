/*
 * kmsg_dump.c — 内核崩溃日志 UDP + 文件 双通道保存
 *
 * 平板 CONFIG_NETCONSOLE=n，无 netpoll 符号，netconsole 不可用。
 * 本模块注册一个 console，把每条 printk 实时：
 *   A) 通过 UDP 发送到接收端（WSL 上的 nc -u -l），崩溃前日志实时可见
 *   B) 追加写入本地文件（需显式传 path= 参数，否则只发 UDP）
 *
 * panic 时注册的 panic_notifier 会尽力同步 flush 两个通道，
 * 确保崩溃瞬间的最后一段日志不因 worker 来不及调度而丢失。
 *
 * 上下文安全：
 *   console write 回调可能在中断/原子上下文被调用，kernel_write/
 *   kernel_sendmsg 会睡眠。因此 write 回调只把数据拷入环形缓冲并
 *   queue_work()，实际发送/写入由 workqueue worker 在进程上下文完成。
 *   UDP socket 与日志文件在模块 init 时创建（进程上下文安全），
 *   发送路径只使用，不重建。panic notifier 里若仍在原子上下文则放弃
 *   （避免死锁加重崩溃）。
 *
 * 依赖的内核符号（平板内核已确认存在）:
 *   register_console, sock_create_kern, kernel_sendmsg, sock_release,
 *   filp_open, filp_close, kernel_write, panic_notifier_list
 *
 * 使用:
 *   insmod kmsg_dump.ko ip=192.168.1.x port=6666
 *   insmod kmsg_dump.ko ip=192.168.1.x port=6666 path=/data/crash_kmsg
 *   接收端: nc -u -l 6666
 */

#include <linux/module.h>
#include <linux/console.h>
#include <linux/notifier.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <net/net_namespace.h>

static char dest_ip[16] = "192.168.1.1";
static int port = 6666;
static char path[256] = "";   /* 空 = 不写文件，只发 UDP */
module_param_string(ip, dest_ip, sizeof(dest_ip), 0644);
module_param(port, int, 0644);
module_param_string(path, path, sizeof(path), 0644);

static struct socket *netcon_sock;
static struct sockaddr_in netcon_addr;
static struct file *log_file;

static struct work_struct netcon_work;
static struct workqueue_struct *netcon_wq;

/* panic notifier：崩溃时尽力同步发送最后缓冲 */
static struct notifier_block netcon_panic_nb;

/* write 回调与 worker 共享的环形缓冲。SIZE 必须是 2 的幂。 */
#define NETCON_BUF_SIZE   (64 * 1024)

static DEFINE_SPINLOCK(netcon_lock);
static char netcon_buf[NETCON_BUF_SIZE];
static size_t netcon_head;   /* 写入位置，单调递增不取模 */
static size_t netcon_tail;   /* 读取位置，单调递增不取模 */

/* ── 通道初始化（模块 init 时调用，进程上下文） ───────────────────── */

static int netcon_init_udp(void)
{
	struct sockaddr_in *sin = &netcon_addr;
	int ret, sndbuf = 256 * 1024;

	ret = sock_create_kern(&init_net, AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			       &netcon_sock);
	if (ret < 0) {
		pr_err("netcon: sock_create_kern failed %d\n", ret);
		return ret;
	}

	/* 预增大 UDP 发送缓冲，减少 MSG_DONTWAIT 下 EAGAIN 丢包 */
	kernel_setsockopt(netcon_sock, SOL_SOCKET, SO_SNDBUF,
			  (char *)&sndbuf, sizeof(sndbuf));

	sin->sin_family = AF_INET;
	sin->sin_port = htons(port);
	if (!in4_pton(dest_ip, -1, (u8 *)&sin->sin_addr, -1, NULL)) {
		pr_err("netcon: invalid IP %s\n", dest_ip);
		sock_release(netcon_sock);
		netcon_sock = NULL;
		return -EINVAL;
	}
	return 0;
}

static int netcon_init_file(void)
{
	if (path[0] == '\0')   /* 未启用文件模式 */
		return 0;

	log_file = filp_open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (IS_ERR(log_file)) {
		pr_err("netcon: 无法打开 %s (%ld)\n", path, PTR_ERR(log_file));
		log_file = NULL;
		return -EINVAL;
	}
	return 0;
}

/* ── 输出 ─────────────────────────────────────────────────────────── */

/* 发送一行 UDP（进程上下文） */
static void netcon_send_udp(char *line, size_t len)
{
	struct msghdr msg;
	struct kvec vec;
	int ret;

	if (IS_ERR_OR_NULL(netcon_sock) || len == 0)
		return;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &netcon_addr;
	msg.msg_namelen = sizeof(netcon_addr);
	msg.msg_flags = MSG_DONTWAIT;

	vec.iov_base = line;
	vec.iov_len = len;

	ret = kernel_sendmsg(netcon_sock, &msg, &vec, 1, len);
	if (ret < 0)
		pr_debug("netcon: send failed %d\n", ret);
}

/* 写一行到文件（进程上下文） */
static void netcon_write_file(char *line, size_t len)
{
	loff_t pos;

	if (IS_ERR_OR_NULL(log_file) || len == 0)
		return;

	pos = i_size_read(file_inode(log_file));
	kernel_write(log_file, line, len, &pos);
}

/* 双通道输出一行 */
static void netcon_emit(char *line, size_t len)
{
	netcon_send_udp(line, len);
	netcon_write_file(line, len);
}

/* ── 环形缓冲 ─────────────────────────────────────────────────────── */

/* 从环形缓冲取一段数据（最多 maxlen 字节），返回实际长度 */
static size_t netcon_dequeue(char *dst, size_t maxlen)
{
	size_t avail, first;
	unsigned long flags;

	spin_lock_irqsave(&netcon_lock, flags);
	/* head/tail 单调递增，无符号差值天然正确，无需取模 */
	avail = netcon_head - netcon_tail;
	if (avail > maxlen)
		avail = maxlen;
	if (avail) {
		first = NETCON_BUF_SIZE - (netcon_tail & (NETCON_BUF_SIZE - 1));
		if (first > avail)
			first = avail;
		memcpy(dst, netcon_buf + (netcon_tail & (NETCON_BUF_SIZE - 1)),
		       first);
		if (avail > first)
			memcpy(dst + first, netcon_buf, avail - first);
		netcon_tail += avail;
	}
	spin_unlock_irqrestore(&netcon_lock, flags);
	return avail;
}

/* workqueue worker：在进程上下文发送累积的日志 */
static void netcon_work_fn(struct work_struct *work)
{
	char line[1024];

	for (;;) {
		size_t len = netcon_dequeue(line, sizeof(line));

		if (!len)
			break;
		netcon_emit(line, len);
	}
}

/* console write 回调：只拷贝 + queue_work，不 sleep */
static void netcon_write(struct console *con, const char *s, unsigned int count)
{
	size_t first;
	unsigned long flags;

	spin_lock_irqsave(&netcon_lock, flags);

	/* 满：丢弃最旧，为新数据腾出空间 */
	if (count > NETCON_BUF_SIZE)
		count = NETCON_BUF_SIZE;
	if (netcon_head - netcon_tail + count > NETCON_BUF_SIZE)
		netcon_tail = netcon_head + count - NETCON_BUF_SIZE;

	/* 分段 memcpy，避免逐字节持锁 */
	first = NETCON_BUF_SIZE - (netcon_head & (NETCON_BUF_SIZE - 1));
	if (first > count)
		first = count;
	memcpy(netcon_buf + (netcon_head & (NETCON_BUF_SIZE - 1)), s, first);
	if (count > first)
		memcpy(netcon_buf, s + first, count - first);
	netcon_head += count;

	spin_unlock_irqrestore(&netcon_lock, flags);

	queue_work(netcon_wq, &netcon_work);
}

/* ── panic notifier ────────────────────────────────────────────────── */

/*
 * panic 流程会先打印 panic trace（走 console → netcon_write → queue_work），
 * 然后调用本回调。此时若 CPU 仍在进程上下文（非原子），同步发送缓冲中的
 * 最后一段日志，确保崩溃前的输出不因 worker 来不及调度而丢失。
 * 若在原子上下文，kernel_sendmsg/kernel_write 会睡眠死锁，放弃发送
 * （workqueue 已尽力）。
 */
static int netcon_panic_cb(struct notifier_block *nb, unsigned long event, void *ptr)
{
	char line[1024];
	size_t len;

	/* 原子上下文（硬中断/软中断/NMI/持锁）不能睡眠，放弃发送 */
	if (in_irq() || in_softirq() || in_nmi() || in_atomic())
		return NOTIFY_DONE;

	netcon_emit("===== KERNEL PANIC =====\n",
		    strlen("===== KERNEL PANIC =====\n"));

	/* 尽力发送缓冲里的剩余数据 */
	while ((len = netcon_dequeue(line, sizeof(line))) > 0)
		netcon_emit(line, len);

	netcon_emit("===== END PANIC =====\n",
		    strlen("===== END PANIC =====\n"));

	return NOTIFY_OK;
}

static struct console netcon_console = {
	.name   = "netcon",
	.write  = netcon_write,
	.flags  = CON_PRINTBUFFER | CON_ENABLED,
	.index  = -1,
};

static int __init netcon_init(void)
{
	/* 通道初始化（进程上下文，可睡眠） */
	if (netcon_init_udp() < 0)
		return -EINVAL;
	if (netcon_init_file() < 0) {
		sock_release(netcon_sock);
		netcon_sock = NULL;
		return -EINVAL;
	}

	INIT_WORK(&netcon_work, netcon_work_fn);
	netcon_wq = create_singlethread_workqueue("netcon");
	if (!netcon_wq) {
		pr_err("netcon: create workqueue failed\n");
		sock_release(netcon_sock);
		netcon_sock = NULL;
		if (!IS_ERR_OR_NULL(log_file))
			filp_close(log_file, NULL);
		log_file = NULL;
		return -ENOMEM;
	}

	/* 注册 panic notifier（崩溃时同步补发） */
	netcon_panic_nb.notifier_call = netcon_panic_cb;
	atomic_notifier_chain_register(&panic_notifier_list, &netcon_panic_nb);

	/* 注册 console */
	register_console(&netcon_console);

	pr_info("netcon: 内核日志 → %s:%d + %s (console + panic notifier registered)\n",
		dest_ip, port, path);
	return 0;
}

static void __exit netcon_exit(void)
{
	unregister_console(&netcon_console);

	atomic_notifier_chain_unregister(&panic_notifier_list, &netcon_panic_nb);

	flush_workqueue(netcon_wq);
	destroy_workqueue(netcon_wq);

	if (!IS_ERR_OR_NULL(netcon_sock))
		sock_release(netcon_sock);
	netcon_sock = NULL;

	if (!IS_ERR_OR_NULL(log_file))
		filp_close(log_file, NULL);
	log_file = NULL;

	pr_info("netcon: 已卸载\n");
}

module_init(netcon_init);
module_exit(netcon_exit);
MODULE_LICENSE("GPL");
