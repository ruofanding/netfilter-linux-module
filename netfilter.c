#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct iphdr *ip_header;
struct tcphdr *tcp_header;
static struct nf_hook_ops nfho;

unsigned char* payload;
unsigned int payload_len;
int i;

static unsigned int hook_func(unsigned int hooknum,
							struct sk_buff * skb,
							const struct net_device *in,
							const struct net_device *out,
							int (*okfn)(struct sk_buff *))
{
	if(skb)
	{
		ip_header = (struct iphdr *) skb_network_header(skb);
		if (ip_header->protocol == IPPROTO_TCP)
		{
		//printk(KERN_ALERT "%d, %d, Bool:%d", skb->len, skb->data_len, skb_is_nonlinear(skb));
			char* frag_addr;
			if(skb_is_nonlinear(skb))
			{
				for (i = skb_shinfo(skb)->nr_frags - 1; i >= 0; i--)
				{
					frag_addr = skb_frag_address_safe(&skb_shinfo(skb)->frags[i]);
					if(frag_addr != NULL)
						printk(KERN_ALERT "%.*s", skb_frag_size(&skb_shinfo(skb)->frags[i]), frag_addr);
				}

			}else{
				tcp_header = (struct tcphdr *) skb_transport_header(skb);
				payload = (unsigned char*)tcp_header + tcp_hdrlen(skb);
				payload_len = (unsigned char*)skb_end_pointer(skb) - payload;
				printk(KERN_ALERT "%.*s\n", payload_len, payload);
			}
				
		}
	}
	return NF_ACCEPT;
}


static int __init init_main(void)
{
	nfho.hook = hook_func;
	nfho.hooknum = 3;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho);
	
	printk(KERN_ALERT "Netfilter module has been inserted\n");
	
	return 0;
}

static void __exit cleanup_main(void)
{
	nf_unregister_hook(&nfho);
}

module_init(init_main);
module_exit(cleanup_main);

MODULE_LICENSE("GPLv3");
MODULE_AUTHOR("Ruofan Ding");
MODULE_DESCRIPTION("Net filter basic");
