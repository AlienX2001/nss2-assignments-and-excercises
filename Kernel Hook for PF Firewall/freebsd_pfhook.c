#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/pfil.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/vnet.h>
#include <netinet/ip_var.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>

static pfil_return_t icmp_packet_handler(struct mbuf **mp, struct ifnet *ifp, int dir, void *ctx, struct inpcb *inp)
{
    struct ip *iphdr;
    struct icmphdr *icmp;

    iphdr = mtod(*mp,struct ip *);

    if(iphdr->ip_p != IPPROTO_ICMP){
    	return PFIL_PASS;
    }
    else{
	
	icmp = (struct icmphdr *)((caddr_t)iphdr + sizeof(struct ip));
	if(icmp->icmp_type == ICMP_ECHO){
		printf("ICMP echo Detected\n");
    		return PFIL_DROPPED;
	}
	else{
		return PFIL_PASS;
	}
    }
}

static pfil_return_t tcpudp_packet_handler(struct mbuf **mp, struct ifnet *ifp, int dir, void *ctx, struct inpcb *inp)
{
    struct ip *iphdr;
    struct tcphdr *tcp;
    struct udphdr *udp;

    iphdr = mtod(*mp,struct ip *);

    if(iphdr->ip_p == IPPROTO_TCP){
    	tcp = (struct tcphdr *)((caddr_t)iphdr + sizeof(struct ip));
	if(ntohs(tcp->th_dport) < 1024){
		return PFIL_PASS;
	}
	else{
		printf("TCP >= 1024 port detected\n");
		return PFIL_DROPPED;
	}
    }
    else if(iphdr->ip_p == IPPROTO_UDP){
	udp = (struct udphdr *)((caddr_t)iphdr + sizeof(struct ip));
	if(ntohs(udp->uh_dport) < 1024){
		return PFIL_PASS;
	}
	else{
		printf("UDP >= 1024 port detected\n");
		return PFIL_DROPPED;
	}
    }
    else{
        return PFIL_PASS;
    }
}

static struct pfil_hook_args hook_args_icmp, hook_args_tcpudp;
static pfil_hook_t phk_icmp, phk_tcpudp;
static struct pfil_link_args link_args_icmp, link_args_tcpudp;

static int ModLoadHandler(module_t mod, int event, void *arg)
{
    switch (event) {
    case MOD_LOAD:
	printf("Before loading hook: %p \n",phk_icmp);
        /* Set up the pfil hook args */
        memset(&hook_args_icmp, 0, sizeof(hook_args_icmp));
        hook_args_icmp.pa_version = PFIL_VERSION;
	hook_args_icmp.pa_flags = PFIL_IN;
	hook_args_icmp.pa_type = PFIL_TYPE_IP4;
	hook_args_icmp.pa_func = icmp_packet_handler;
	hook_args_icmp.pa_ruleset = NULL;
	hook_args_icmp.pa_modname = "freebsd_pfhook";
	hook_args_icmp.pa_rulname = "icmp-in";
	
	memset(&hook_args_tcpudp, 0, sizeof(hook_args_tcpudp));
        hook_args_tcpudp.pa_version = PFIL_VERSION;
        hook_args_tcpudp.pa_flags = PFIL_IN;
        hook_args_tcpudp.pa_type = PFIL_TYPE_IP4;
        hook_args_tcpudp.pa_func = tcpudp_packet_handler;
        hook_args_tcpudp.pa_ruleset = NULL;
        hook_args_tcpudp.pa_modname = "freebsd_pfhook";
        hook_args_tcpudp.pa_rulname = "tcpudp-in";

	/* Register the pfil head hook with the kernel*/
	phk_icmp = pfil_add_hook(&hook_args_icmp);
	phk_tcpudp = pfil_add_hook(&hook_args_tcpudp);

	/* Set up the pfil link args*/
	link_args_icmp.pa_version = PFIL_VERSION;
	link_args_icmp.pa_flags = PFIL_IN | PFIL_HEADPTR | PFIL_HOOKPTR;
	link_args_icmp.pa_head = V_inet_pfil_head;
	link_args_icmp.pa_hook = phk_icmp;

	link_args_tcpudp.pa_version = PFIL_VERSION;
        link_args_tcpudp.pa_flags = PFIL_IN | PFIL_HEADPTR | PFIL_HOOKPTR;
        link_args_tcpudp.pa_head = V_inet_pfil_head;
        link_args_tcpudp.pa_hook = phk_tcpudp;

	/* Linking the pfil head to hook*/
	pfil_link(&link_args_icmp);
	pfil_link(&link_args_tcpudp);

	printf("After loading hook: %p\n",phk_icmp);
	break;

    case MOD_UNLOAD:
        /* Unregister the pfil hook and register*/
	printf("Before Unloading hook: %p\n",phk_icmp);
	pfil_remove_hook(phk_icmp);
	pfil_remove_hook(phk_tcpudp);
        break;
    default:
        break;
    } 
    return 0;
}

/* Declare the module to the kernel */
static moduledata_t module_data = {
    "freebsd_pfhook", /* module name */
    ModLoadHandler, /* event handler function */
    NULL /* extra data */
};

/* Register the module with the kernel */
DECLARE_MODULE(freebsd_pfhook, module_data, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
