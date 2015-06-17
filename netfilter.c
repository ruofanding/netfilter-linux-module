#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/string.h>

struct iphdr *ip_header;
struct tcphdr *tcp_header;
static struct nf_hook_ops nfho;

unsigned char* payload;
unsigned int payload_len;
int i;

int IsTcpPayloadWebProxyRequest(const char* payload, size_t len);
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
			int frag_len;
			if(skb_is_nonlinear(skb))
			{
				for (i = skb_shinfo(skb)->nr_frags - 1; i >= 0; i--)
				{
					frag_addr = skb_frag_address_safe(&skb_shinfo(skb)->frags[i]);
					frag_len = skb_frag_size(&skb_shinfo(skb)->frags[i]);
					if(frag_addr != NULL)
					{
						printk(KERN_ALERT "%.*s\n", frag_len, frag_addr);
						printk(KERN_ALERT "Is http proxy:%d\n",  IsTcpPayloadWebProxyRequest(frag_addr, frag_len)); 
					}
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

int IsTcpPayloadWebProxyRequest(const char* payload, size_t payload_len)
{
	int i, j;
	static const char* HTTP_METHODS[] = {"GET", "PUT", "POST", "DELETE", "CONNECT"};
	static const int HTTP_METHODS_LEN[] = {3, 3, 4, 6, 7};
	static const char* HTTP_VERSION[]={"HTTP/1.0", "HTTP/1.1"};
	

	char* version_pos;	
	for(i = 0; i < 5; i++)
	{
		if(payload_len > HTTP_METHODS_LEN[i] + 1 && strncmp(HTTP_METHODS[i], payload, HTTP_METHODS_LEN[i]) == 0)
		{
			if(payload[HTTP_METHODS_LEN[i] + 1] != '/')
			{
				for(j = 0; j < 2; j++)
				{
					version_pos = strnstr(payload, HTTP_VERSION[j], payload_len);
					if(version_pos != NULL)
					{
						printk(KERN_ALERT "url%.*s\n", version_pos - payload - HTTP_METHODS_LEN[i] - 2, payload + HTTP_METHODS_LEN[i] + 1);
						return 3;
					}	
				}
				return 2;
			}else{
				return 1;
			}
		}
	}

	return 0;
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
