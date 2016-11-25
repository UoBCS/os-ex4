#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>
#include <net/tcp.h>

// QUESTIONS
// - Should I open the file or pass the string from user space

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

static int proc_open = 0;
static struct proc_dir_entry *proc_file;
//static struct list_head f_rule_list;
static struct f_rule f_rule_list;
//INIT_LIST_HEAD(&f_rule_list);

DEFINE_MUTEX(proc_lock);

unsigned int firewall_ext_hook (const struct nf_hook_ops *ops,
				    struct sk_buff *skb,
				    const struct net_device *in,
				    const struct net_device *out,
				    int (*okfn)(struct sk_buff *)) {

	return NF_ACCEPT;
}

// W:rules_string
ssize_t k_write(struct file *file, const char __user *buffer, size_t count, loff_t *offset)
{
	// Parse input (error handling is done in the user space)
	int len = count + 1;
	char *buf = kmalloc(sizeof(char) * len, GFP_KERNEL), cmd;
	
	
	strncpy_from_user(buf, buffer, len - 1);
	buf[len - 1] = '\0';

	printk("Buffer: %s\n", buf);

	// Extract command
	cmd = buf[0];
	printk("This is cmd: %c\n", cmd);

	if (cmd == LIST_RULES) {
		struct f_rule *rule;
		list_for_each_entry(rule, &f_rule_list.list, list) {
			printk("Firewall rule: %d %s\n", rule->port, rule->program);
		}
	} else if (cmd == ADD_RULES) {
		char *rules = buf + 2, port[10], *program = NULL;
		int rules_len = strlen(rules), i, c = 0, parsing_phase = 1, dec_port;

		// Remove previous rules
		printk("HERE WE ARE!");

		// Add new rules
		for (i = 0; i < rules_len; i++) {
			if (rules[i] == '\n') {
				// Save program and rule
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
				port[c] = '\0';
				kstrtoint(port, 0, &dec_port);
				c = 0;
				parsing_phase = 2;
				continue;
			}

			if (parsing_phase == 1) {
				port[c++] = rules[i];
			} else {
				program = krealloc(program, sizeof(char) * (c + 1), GFP_KERNEL);
				program[c++] = rules[i];
			}
		}

		// Check rules

	}

	// Free buf
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
	printk (KERN_INFO "proc file opened\n");
	mutex_unlock(&proc_lock);
	try_module_get(THIS_MODULE);

	return 0;
}

int procfs_close(struct inode *inode, struct file *file)
{
	mutex_lock(&proc_lock);
	proc_open--;
	printk (KERN_INFO "proc file closed\n");
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

/*static struct nf_hook_ops firewall_ext_ops = {
	.hook 		= firewall_ext_hook,
	.pf 		= PF_INET,
	.priority 	= NF_IP_PRI_FIRST,
	.hooknum 	= NF_INET_LOCAL_OUT
};*/

int init_module(void)
{
	printk(KERN_INFO "Initializing firewallExtension module:\n");

	// Initialise list
	INIT_LIST_HEAD(&f_rule_list.list);

	// Create proc file
	proc_file = proc_create_data(PROC_ENTRY_FILENAME, 0666, NULL, &fops, NULL); // 0644
	if (proc_file == NULL) {
		printk(KERN_ALERT "Error: Could not initialize /proc/%s\n", PROC_ENTRY_FILENAME);
		return -ENOMEM;
	}

	printk(KERN_INFO "/proc/%s created\n", PROC_ENTRY_FILENAME);

	// Register firewall hook
	/*int errno = nf_register_hook(&firewall_ext_ops);
	if (errno) {
		printk(KERN_ALERT "Firewall extension could not be registered!\n");
		return errno;
	}

	printk(KERN_INFO "Firewall extension module loaded\n");*/

	return 0;
}

void cleanup_module(void)
{
	remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
	printk(KERN_INFO "Firewall extensions module unloaded\n");
}
