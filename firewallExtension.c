#include <linux/module.h>  /* Needed by all modules */
MODULE_AUTHOR ("1230806");
MODULE_DESCRIPTION ("Extensions to the firewall") ;
MODULE_LICENSE("GPL");



int init_module(void)
{
	printk(KERN_INFO "Initializing kernel module:\n");

  	// A non 0 return means init_module failed; module can't be loaded.
	return 0;
}


void cleanup_module(void)
{
	printk(KERN_INFO "Firewall extensions module unloaded\n");
}  

