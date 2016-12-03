#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <net/tcp.h>

MODULE_AUTHOR ("1466610");
MODULE_DESCRIPTION ("Extensions to the firewall");
MODULE_LICENSE("GPL");

// Data structures
// -------------------------------------------------------------------
struct f_rule {
	int port;
	char *program;
	struct list_head list;
};

// Globals
// -------------------------------------------------------------------
#define PROC_ENTRY_FILENAME "firewallExtension"
#define LIST_RULES 'L'
#define ADD_RULES 'W'
#define BUFFERSIZE 80

static int proc_open = 0;
static struct proc_dir_entry *proc_file;
static struct f_rule f_rule_list;

DEFINE_MUTEX(proc_lock);
DEFINE_MUTEX(rules_lock);

void get_executable(void)
{
	char *ret_path = NULL;
	struct path path;
	pid_t mod_pid;
	struct dentry *proc_dentry;
	struct dentry *parent = NULL;

	char cmd_proc_f[BUFFERSIZE];
	int res;

	mod_pid = current->pid;
	snprintf(cmd_proc_f, BUFFERSIZE, "/proc/%d/exe", mod_pid);
	res = kern_path(cmd_proc_f, LOOKUP_FOLLOW, &path);
	if (res) {
		printk (KERN_INFO "Could not get dentry for %s!\n", cmd_proc_f);
		//return -EFAULT;
	}

	//proc_dentry = path.dentry;
	/*parent = path.dentry;
	ret_path = krealloc(ret_path, sizeof(char) * strlen(parent->d_name.name), GFP_KERNEL);
	strcpy(ret_path, parent->d_name.name);*/
	// do a strncpy
	//printk (KERN_INFO "The name is %s\n", proc_dentry->d_name.name);

	//parent = proc_dentry->d_parent;
	int idx = 0, len;
	do {

		len = strlen(parent->d_name.name) + 1;
		ret_path = krealloc(ret_path, sizeof(char) * (idx + len), GFP_KERNEL);
		strncpy(ret_path + idx, strcat("/", parent->d_name.name), len);

		idx += len;
		parent = parent->d_parent;
	} while (parent && strcmp(parent->d_name.name, "/") != 0);

	ret_path[idx] = '\0';
	printk(KERN_INFO "Look at this exe: %s\n", ret_path);

	//return ret_path;
}

unsigned int firewall_ext_hook (unsigned int hooknum, //const struct nf_hook_ops *ops,
				    struct sk_buff *skb,
				    const struct net_device *in,
				    const struct net_device *out,
				    int (*okfn)(struct sk_buff *)) {

	struct tcphdr *tcp, _tcph;
	struct sock *sk;

	sk = skb->sk;
	if (!sk) {
		printk (KERN_INFO "firewallExtension: ERROR, netfilter called with empty socket!\n");;
		return NF_ACCEPT;
	}

	if (sk->sk_protocol != IPPROTO_TCP) {
		printk (KERN_INFO "firewallExtension: ERROR, netfilter called with non-TCP-packet.\n");
		return NF_ACCEPT;
	}

	// Get the tcp-header for the packet
	tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
	if (!tcp) {
		printk (KERN_INFO "firewallExtension: ERROR, could not get tcp-header.\n");
		return NF_ACCEPT;
	}
	if (tcp->syn) {
		if (in_irq() || in_softirq()) {
			printk(KERN_INFO "firewallExtension: ERROR, not in user context - retry packet\n");
			return NF_ACCEPT;
		}

		// Get executable
		get_executable();

		/*
		A firewall rule consists of a port number and a filename (the full path) of a program separated by a space,
		meaning that the corresponding program is allowed to make outgoing connections on this TCP-port.
		If there is no rule for a given port, any program should be allowed to make outgoing connections on this port.
		A connection is not allowed when rules for the port exist, but the program trying to establish the connection is
		not in the list of allowed programs.
		*/
		struct f_rule *rule;
		int no_rule_for_port = 1;
		list_for_each_entry(rule, &f_rule_list.list, list) {
			if (ntohs(tcp->dest) == rule->port) {
				no_rule_for_port = 0;

				/*if (program == rule->program)
					return NF_ACCEPT;*/
			}
		}

		if (!no_rule_for_port) {
			tcp_done(sk);
			printk(KERN_INFO "firewallExtension: connection shut down\n");
			return NF_DROP;
		}

		/*if (ntohs (tcp->dest) == 80) {
			tcp_done(sk);
			printk(KERN_INFO "firewallExtension: connection shut down\n");
			return NF_DROP;
		}*/
	}

	return NF_ACCEPT;
}

ssize_t k_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset)
{
	

	// Parse input (error handling is done in the user space)
	int len = count + 1;
	char *buf = kmalloc(sizeof(char) * len, GFP_KERNEL), cmd;
	struct f_rule *rule;
	
	
	strncpy_from_user(buf, buffer, len - 1);
	buf[len - 1] = '\0';

	// Extract command
	// ---------------
	cmd = buf[0];

	if (cmd == LIST_RULES) {
		list_for_each_entry(rule, &f_rule_list.list, list) {
			printk("Firewall rule: %d %s\n", rule->port, rule->program);
		}
	} else if (cmd == ADD_RULES) {
		char *rules = buf + 2, port[10], *program = NULL;
		int rules_len = strlen(rules), i, c = 0, parsing_phase = 1, dec_port;

		// Remove previous rules
		// ---------------------
		struct f_rule *tmp;
		list_for_each_entry_safe(rule, tmp, &f_rule_list.list, list) {
			list_del(&rule->list);
			kfree(rule);
		}

		// Add new rules
		// -------------
		for (i = 0; i < rules_len; i++) {
			if (rules[i] == '\n') {
				// Save program and rule
				// ---------------------
				program[c] = '\0';

				struct f_rule *new_rule = kmalloc(sizeof(struct f_rule), GFP_KERNEL);
				new_rule->port = dec_port;
				new_rule->program = kmalloc(sizeof(char) * (strlen(program) + 1), GFP_KERNEL);
				strcpy(new_rule->program, program);
				INIT_LIST_HEAD(&new_rule->list);
				list_add(&new_rule->list, &f_rule_list.list);

				kfree(program);
				program = NULL;
				c = 0;
				parsing_phase = 1;
				continue;
			} else if (rules[i] == ' ' && parsing_phase == 1) {
				// Save port
				// ---------
				port[c] = '\0';
				kstrtoint(port, 0, &dec_port);
				c = 0;
				parsing_phase = 2;
				continue;
			}

			// Check parsing phase
			// -------------------
			if (parsing_phase == 1) {
				port[c++] = rules[i];
			} else {
				program = krealloc(program, sizeof(char) * (c + 1), GFP_KERNEL);
				program[c++] = rules[i];
			}
		}
	}

	kfree(buf);

	return count;
}

int procfs_open(struct inode *inode, struct file *file)
{
	mutex_lock(&proc_lock);
	if (proc_open) {
		mutex_unlock(&proc_lock);
		return -EAGAIN;
	}
	proc_open++;
	printk (KERN_INFO "firewallExtension: proc file opened\n");
	mutex_unlock(&proc_lock);
	try_module_get(THIS_MODULE);

	return 0;
}

int procfs_close(struct inode *inode, struct file *file)
{
	mutex_lock(&proc_lock);
	proc_open--;
	printk (KERN_INFO "firewallExtension: proc file closed\n");
	mutex_unlock(&proc_lock);

	module_put(THIS_MODULE);
	return 0;
}

static struct file_operations fops = {
	.owner 		= THIS_MODULE,
	.write 		= k_write,
	.open 		= procfs_open,
	.release 	= procfs_close
};

static struct nf_hook_ops firewall_ext_ops = {
	.hook 		= firewall_ext_hook,
	.pf 		= PF_INET,
	.priority 	= NF_IP_PRI_FIRST,
	.hooknum 	= NF_INET_LOCAL_OUT
};

int init_module(void)
{
	printk(KERN_INFO "firewallExtension: initializing module\n");

	// Initialise list
	INIT_LIST_HEAD(&f_rule_list.list);

	// Create proc file
	proc_file = proc_create_data(PROC_ENTRY_FILENAME, 0666, NULL, &fops, NULL); // 0644
	if (proc_file == NULL) {
		printk(KERN_ALERT "firewallExtension: ERROR, could not initialize /proc/%s\n", PROC_ENTRY_FILENAME);
		return -ENOMEM;
	}

	printk(KERN_INFO "firewallExtension: /proc/%s created\n", PROC_ENTRY_FILENAME);

	// Register firewall hook
	int errno = nf_register_hook(&firewall_ext_ops);
	if (errno) {
		printk(KERN_ALERT "firewallExtension: ERROR, netfilter hook could not be registered: %d\n", errno);
		return errno;
	}

	printk(KERN_INFO "firewallExtension: module loaded\n");

	return 0;
}

void cleanup_module(void)
{
	remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
	nf_unregister_hook(&firewall_ext_ops);
	printk(KERN_INFO "firewallExtension: module unloaded\n");
}
