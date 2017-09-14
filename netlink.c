#include <linux/module.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>

#define NETLINK_USER 31

struct sock *nl_sk = NULL;

const char *msg = "success";

struct command {
	const char *name;
	struct sk_buff *(*executor)(void *);
};

struct sk_buff *new_success_msg(void) {
	struct sk_buff *skb_out;
	struct nlmsghdr *nlh;

	skb_out = nlmsg_new(0, 0);
	if (skb_out) {
		nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, 0, 0);
		NETLINK_CB(skb_out).dst_group = 0;
	} else {
		printk(KERN_ERR "Failed to allocate new skb\n");
	}

	return skb_out;
}

struct sk_buff *create_target(void *name) {
	printk(KERN_INFO "shadowpayload: create_target(name=%s)\n", (char *)name);
	return new_success_msg();
}

struct sk_buff *remove_target(void *name) {
	printk(KERN_INFO "shadowpayload: remove_target(name=%s)\n", (char *)name);
	return new_success_msg();
}

struct sk_buff *set_cipher(void *cipher) {
	printk(KERN_INFO "shadowpayload: set_cipher(cipher=%s)\n", (char *)cipher);
	return new_success_msg();
}
struct sk_buff *set_key(void *params) {
	char *size = (char *)params;
	void *key = params + strlen(size) + 1;
	printk(KERN_INFO "shadowpayload: set_cipher(size=%sbits, key=****)\n", size);
	return new_success_msg();
}

struct command commands[] = {
	{ .name = "create_target", .executor = create_target },
	{ .name = "remove_target", .executor = remove_target },
	{ .name = "set_cipher", .executor = set_cipher },
	{ .name = "set_key", .executor = set_key },
};

static void shadowpayload_nl_recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	int supported_commands = sizeof(commands) / sizeof(struct command);
	int res, i;

	nlh = (struct nlmsghdr *)skb->data;
	for (i = 0; i < supported_commands; i++) {
		char *cmd = (char *)nlmsg_data(nlh);
		if (strcmp(commands[i].name, cmd) == 0) {
			skb_out = commands[i].executor(nlmsg_data(nlh) + strlen(cmd) + 1);
			break;
		}
	}

	if (i >= supported_commands) {
		printk(KERN_ERR "shadowpayload: Unrecognized commands\n");
		return;
	}

	if (skb_out) {
		res = nlmsg_unicast(nl_sk, skb_out, nlh->nlmsg_pid);
		if (res < 0)
			printk(KERN_ERR "shadowpayload: Error while sending back to user\n");
	}
}

static int __init shadowpayload_init(void)
{
	struct netlink_kernel_cfg cfg = (struct netlink_kernel_cfg) {
		.input = shadowpayload_nl_recv_msg,
	};

	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	if (!nl_sk) {
		printk(KERN_ALERT "shadowpayload: Error creating socket.\n");
		return -10;
	}

	return 0;
}

static void __exit shadowpayload_exit(void)
{
	netlink_kernel_release(nl_sk);
}

module_init(shadowpayload_init);
module_exit(shadowpayload_exit);

MODULE_LICENSE("GPL");
