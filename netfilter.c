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

const int isolation = 1;

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
			// char* frag_addr;
			// int frag_len;
			// if(skb_is_nonlinear(skb))
			// {
			// 	for (i = skb_shinfo(skb)->nr_frags - 1; i >= 0; i--)
			// 	{
			// 		frag_addr = skb_frag_address_safe(&skb_shinfo(skb)->frags[i]);
			// 		frag_len = skb_frag_size(&skb_shinfo(skb)->frags[i]);
			// 		if(frag_addr != NULL)
			// 		{
			// 			printk(KERN_ALERT "%.*s\n", frag_len, frag_addr);
			// 			printk(KERN_ALERT "Is http proxy:%d\n",  IsTcpPayloadWebProxyRequest(frag_addr, frag_len)); 
			// 		}
			// 	}

			// }else{
			// 	tcp_header = (struct tcphdr *) skb_transport_header(skb);
			// 	payload = (unsigned char*)tcp_header + tcp_hdrlen(skb);
			// 	payload_len = (unsigned char*)skb_end_pointer(skb) - payload;
			// 	printk(KERN_ALERT "%.*s\n", payload_len, payload);
			// }
			;	
		}else if (ip_header->protocol == IPPROTO_UDP && isolation){
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}
int test(struct sk_buff* skb)
{
	char tmp[10];
	const int URL_MAX_LEN = 500;
	char url[URL_MAX_LEN];

	int i, j;
	const char* HTTP_METHODS[] = {"GET", "PUT", "POST", "DELETE", "CONNECT"};
	const int HTTP_METHODS_LEN[] = {3, 3, 4, 6, 7};
	const int HTTP_METHOD_MAX_LEN = 7;
	const char* HTTP_VERSION[]={"HTTP/1.1", "HTTP/1.0"};
	const int HTTP_VERSION_LEN = 8;
	int space_offset;
	int url_len;
	
				
	/*if(skb_headlen(skb) == 52)
	{
		printk(KERN_ALERT "BIG %d\n", tcp_hdrlen(skb));
		printk(KERN_ALERT "%pI4 %pI4\n",&ip_hdr(skb)->saddr, &ip_hdr(skb)->daddr); 
	}*/
	int payload_offset;

	payload_offset = tcp_hdrlen(skb) + sizeof(struct iphdr);
	if(skb_copy_bits(skb, payload_offset, tmp, HTTP_METHOD_MAX_LEN + 2) != 0)
	{
		goto check_exit;
	}

	for(i = 0; i < 5; i++)
	{
		if(strncmp(HTTP_METHODS[i], tmp, HTTP_METHODS_LEN[i]) == 0)
		{
			
			if(tmp[HTTP_METHODS_LEN[i] + 1] != '/')
			{
				space_offset = find_char_offset(skb, payload_offset + HTTP_METHODS_LEN[i] + 2, ' ');
				if(space_offset != -1)
				{
					printk(KERN_ALERT "Find space\n");
					if(skb_copy_bits(skb, space_offset + 1,	tmp, HTTP_VERSION_LEN) == 0)
					{
						printk(KERN_ALERT "copied!\n");
						if(strncmp(HTTP_VERSION[0], tmp, HTTP_VERSION_LEN) == 0 ||
							strncmp(HTTP_VERSION[1], tmp, HTTP_VERSION_LEN) == 0)
						{
							url_len = space_offset - (payload_offset + HTTP_METHODS_LEN[i] + 2);
							//skb_copy_bits(skb, payload_offset + HTTP_METHODS_LEN[i] + 2, url, url_len); 
							printk(KERN_ALERT "GOOD! %d\n", url_len);	

						}
					}
				}
				
			}
			break;
		}
	}

check_exit:
	return 0;
}

int find_char_offset(const struct sk_buff* skb, int offset, char target)
{
	char* ptr;
	char* frag_addr;
	int frag_len;
	int current_offset;
	
	//There is data inside skb, so search the remaining data before search fragments.
	if(skb->len - skb->data_len > offset)
	{
		current_offset = offset;
		for(ptr = skb->data + offset; ptr < skb_tail_pointer(skb); ptr++)
		{
			if(*ptr == target)
			{
				return current_offset;
			}
			current_offset++;
		}
	}else{
		current_offset = skb->len - skb->data_len;
	}

	for (i = skb_shinfo(skb)->nr_frags - 1; i >= 0; i--)
	{
		frag_addr = skb_frag_address_safe(&skb_shinfo(skb)->frags[i]);
		frag_len = skb_frag_size(&skb_shinfo(skb)->frags[i]);
		printk(KERN_ALERT "%.*s\n", frag_len, frag_addr);
		for(ptr = frag_addr; ptr <= frag_addr + frag_len; ptr++)
		{
			if(current_offset >= offset && *ptr == target)
			{
				return current_offset;
			}
			current_offset++;
		}
	}
	return -1;
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
