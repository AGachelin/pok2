#include <linux/init.h>
#include <linux/module.h>
   
static int my_init(void)
{
    printk(KERN_INFO "Hello world.\n");
    return  0;
}
   
static void my_exit(void)
{
    printk(KERN_INFO "Goodbye world.\n");

    return;
}
   
module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("");