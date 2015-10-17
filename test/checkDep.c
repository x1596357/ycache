#include <linux/init.h>
#include <linux/module.h>
MODULE_LICENSE("Dual BSD/GPL");
static int check_init(void)
{
	printk(KERN_INFO "Check dependency start:\n");
#ifdef CONFIG_CLEANCACHE
	printk(KERN_INFO "cleancache exists\n");
#else
	printk(KERN_INFO "cleancache not exists\n");
#endif
#ifdef CONFIG_FRONTSWAP
	printk(KERN_INFO "frontswap exists\n");
#else
	printk(KERN_INFO "frontswap not exists\n");
#endif
#ifdef CONFIG_DEBUG_FS
	printk(KERN_INFO "debugfs exists\n");
#else
	printk(KERN_INFO "debugfs not exists\n");
#endif
	printk(KERN_INFO "Check dependency end\n");
	return 0;
}
static void check_exit(void) {}
module_init(check_init);
module_exit(check_exit);