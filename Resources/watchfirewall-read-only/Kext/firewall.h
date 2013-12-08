#ifndef WATCH_FIREWALL_H
#define WATCH_FIREWALL_H

#include <mach/vm_types.h>
#include <mach/kmod.h>
#include <sys/socket.h>
#include <sys/kpi_socket.h>
#include <sys/kpi_mbuf.h>
#include <sys/kpi_socket.h>
#include <sys/kpi_socketfilter.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <netinet/in.h>
#include <kern/locks.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <sys/kern_control.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>

#define CLIENT_DEBUG_MESSAGES

#include "rule.h"
#include "cookie.h"
#include "messages.h"
#include "client.h"



struct __attribute__((visibility("hidden"))) protocol
{
	sflt_handle handle;
	int domain;
	int type;
	int proto;
	int state;
};

struct __attribute__((visibility("hidden"))) Firewall 
{
public:
	bool	firewallUp;
	bool	closing;
	UInt32	countAttachedSockets __attribute__ ((aligned (4)));
	
	volatile SInt32 countSubscribersForInfoSockets __attribute__ ((aligned (4)));
	volatile SInt32 countSubscribersForInfoRules __attribute__ ((aligned (4)));
	volatile SInt32 countSubscribersAsaProviderOfRules __attribute__ ((aligned (4)));
	
#ifdef CLIENT_DEBUG_MESSAGES	
	volatile SInt32 countSubscribersForDebug __attribute__ ((aligned (4)));
#endif CLIENT_DEBUG_MESSAGES	
	
	Rules	rules;
	Applications applications;
	SocketCookies socketCookies;
	
public:

	bool Init();
	bool Free();
	
#pragma mark soket filter functions

	bool RegisterSocketFilters();
	bool UnregisterSocketFilters();
	
	static protocol protocols[];
	static sflt_filter sfltFilter;
	
	static void		Unregistered(sflt_handle handle);
	static errno_t	Attach(void	**cookie, socket_t so);
	static void		Detach(void	*cookie, socket_t so);
	static void		Notify(void *cookie, socket_t so, sflt_event_t event, void *param);
	static int		GetPeerName(void *cookie, socket_t so, sockaddr **sa);
	static int		GetSockName(void *cookie, socket_t so, sockaddr **sa);
	static errno_t	DataIn(void *cookie, socket_t so, const sockaddr *from, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags);
	static errno_t	DataOut(void *cookie, socket_t so, const sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags);
	static errno_t	ConnectIn(void *cookie, socket_t so, const sockaddr *from);
	static errno_t	ConnectOut(void *cookie, socket_t so, const sockaddr *to);
	static errno_t	Bind(void *cookie, socket_t so, const sockaddr *to);
	static errno_t	SetOption(void *cookie, socket_t so, sockopt_t opt);
	static errno_t	GetOption(void *cookie, socket_t so, sockopt_t opt);
	static errno_t	Listen(void *cookie, socket_t so);
	static errno_t	Ioctl(void *cookie, socket_t so, unsigned long request, const char* argp);
	static errno_t	Accept(void *cookie, socket_t so_listen, socket_t so, const sockaddr *local, const sockaddr *remote);
	
#pragma mark clent functions
	kern_ctl_ref kernelControlReference;
	static kern_ctl_reg kernelControlRegistration; 

	IOLock *lockClientsQueue;
	Client *clients;
	
	bool RegisterKernelControl();
	bool UnregisterKernelControl();
	
	static errno_t KcConnect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo);
	static errno_t KcDisconnect(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo);
	static errno_t KcSend(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags);
	static errno_t KcSetSocketOption(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);
	static errno_t KcGetSocketOption(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len);

	void Send(Message *message);
};

extern Firewall firewall;

#endif WATCH_FIREWALL_H
