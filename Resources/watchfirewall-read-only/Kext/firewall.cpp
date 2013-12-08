/*
 *  firewall.c
 *  Watch
 *
 *  Created by Jan Bird on 4/5/09.
 *  Copyright 2009 __MoonLight__. All rights reserved.
 *
 */

#include <sys/kpi_socket.h>
#include "firewall.h"

//////////////helper for debug




////////end helper for debug

Firewall firewall;

protocol Firewall::protocols[] =
{
{0xBACAF000, PF_INET, SOCK_STREAM, IPPROTO_TCP, 0},
{0xBACAF001, PF_INET, SOCK_DGRAM, IPPROTO_UDP, 0},
{0xBACAF002, PF_INET, SOCK_RAW, IPPROTO_ICMP, 0},
{0xBACAF003, PF_INET6, SOCK_STREAM, IPPROTO_TCP, 0},
{0xBACAF004, PF_INET6, SOCK_DGRAM, IPPROTO_UDP, 0},
{0xBACAF005, PF_INET6, SOCK_RAW, IPPROTO_ICMP, 0}/*,
{0xBACAF006, PF_UNIX, SOCK_STREAM, 0, 0}*/

};

sflt_filter Firewall::sfltFilter = {
0xBABABABC,					/* sflt_handle - use a registered creator type - <http://developer.apple.com/data type/> */
SFLT_GLOBAL | SFLT_EXTENDED,/* sf_flags */
(char*)MYBUNDLEID,					/* sf_name - cannot be nil else param err results */
Unregistered,	/* sf_unregistered_func */
Attach,			/* sf_attach_func - cannot be nil else param err results */			
Detach,			/* sf_detach_func - cannot be nil else param err results */
Notify,			/* sf_notify_func */
GetPeerName,	/* sf_getpeername_func */
GetSockName,	/* sf_getsockname_func */
DataIn,			/* sf_data_in_func */
DataOut,		/* sf_data_out_func */
ConnectIn,		/* sf_connect_in_func */
ConnectOut,		/* sf_connect_out_func */
Bind,			/* sf_bind_func */
SetOption,		/* sf_setoption_func */
GetOption,		/* sf_getoption_func */
Listen,			/* sf_listen_func */
Ioctl,			/* sf_ioctl_func */
{sizeof(sflt_filter::sflt_filter_ext), Accept, {NULL,NULL,NULL,NULL,NULL}} /*sf_filter_ext */
};

bool 
Firewall::RegisterSocketFilters()
{
	size_t len_protocols = sizeof(protocols)/sizeof(*protocols);
	
	for(size_t k =0 ; k < len_protocols; k++)
	{
		sfltFilter.sf_handle = protocols[k].handle;
		errno_t retval = sflt_register(&sfltFilter, protocols[k].domain, protocols[k].type, protocols[k].proto);
		if(!retval)
			protocols[k].state = 1;
	}
	
	return true;
}

bool 
Firewall::UnregisterSocketFilters()
{
	size_t len_protocols = sizeof(protocols)/sizeof(*protocols);
	for(size_t k =0 ; k < len_protocols; k++)
	{
		if(protocols[k].state)	
			if(!sflt_unregister(protocols[k].handle))
				protocols[k].state = 0;
	}
	
	//IOLog("unregister soket filters \n");
	return true;
}



#pragma mark socket filter functions
void	
Firewall::Unregistered(sflt_handle handle)
{
	
}

errno_t	
Firewall::Attach(void **cookie, socket_t so)
{
	if(firewall.closing)
		return ENOMEM;
	
	SocketCookie *socketCookie = new SocketCookie;
	
	if(socketCookie == NULL)
	{
		IOLog("can't allocate memory for socket cookie \n");
		return ENOMEM;
	}

	socketCookie->application = firewall.applications.Get();
	
	if(!socketCookie->application)
	{
		delete socketCookie;
		return ENOMEM;
	}
	
	socketCookie->SetSocket(so);
	socketCookie->state = SocketCookieStateALLOWED;//SocketCookieStateUNKNOWN;
	
	*cookie = socketCookie;
	firewall.socketCookies.Add(socketCookie);

#ifdef CLIENT_DEBUG_MESSAGES	
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltAttach(proc_selfpid(), kauth_getuid(), so, socketCookie->sockProtocol);
		firewall.Send(message);
		message->Release();
	}
#endif //CLIENT_DEBUG_MESSAGES	
	
	return KERN_SUCCESS;
}

void	
Firewall::Detach(void *cookie, socket_t so)
{
	if(cookie)
	{
		firewall.socketCookies.Remove((SocketCookie*)cookie)->Free();
	}

	if(firewall.closing)
		return;
	
#ifdef CLIENT_DEBUG_MESSAGES
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltDetach(proc_selfpid(), kauth_getuid(), so);
		firewall.Send(message);
		message->Release();
	}
#endif //CLIENT_DEBUG_MESSAGES
	
}

void	
Firewall::Notify(void *cookie, socket_t so, sflt_event_t event, void *param)
{
	if(firewall.closing)
		return;

#ifdef CLIENT_DEBUG_MESSAGES
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltNotify(proc_selfpid(), kauth_getuid(), so, event);
		firewall.Send(message);
		message->Release();
	}
#endif //CLIENT_DEBUG_MESSAGES
	
	//TODO: change socket connection state
	switch(event)
	{
		case sock_evt_connecting:
			break;
		case sock_evt_connected:
			break;
		case sock_evt_disconnecting:
			break;
		case sock_evt_disconnected:
			break;
		case sock_evt_flush_read:
			break;
		case sock_evt_shutdown:
			break;
		case sock_evt_cantrecvmore:
			break;
		case sock_evt_cantsendmore:
			break;
		case sock_evt_closing:
			break;
		case sock_evt_bound:
			break;
	}
}

int		
Firewall::GetPeerName(void *cookie, socket_t so, struct sockaddr **sa)
{
//	Message *message = Message::CreateTextFromCookie("getpername", (SocketCookie*)cookie);
	if(firewall.closing)
		return KERN_SUCCESS;

#ifdef CLIENT_DEBUG_MESSAGES	
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltGetPeerName(proc_selfpid(), kauth_getuid(), so, *sa);
		firewall.Send(message);
		message->Release();
	}
#endif //CLIENT_DEBUG_MESSAGES
	
	return KERN_SUCCESS;
}


int		
Firewall::GetSockName(void *cookie, socket_t so, struct sockaddr **sa)
{
//	Message *message = Message::CreateTextFromCookie("getsockname", (SocketCookie*)cookie);
	if(firewall.closing)
		return KERN_SUCCESS;

#ifdef CLIENT_DEBUG_MESSAGES
	if(firewall.countSubscribersForDebug)
	{
		Message* message = Message::CreateSfltGetSockName(proc_selfpid(), kauth_getuid(), so, *sa);
		firewall.Send(message);
		message->Release();
	}	
#endif //CLIENT_DEBUG_MESSAGES

	return KERN_SUCCESS;
}


errno_t	
Firewall::DataIn(void *cookie, socket_t so, const sockaddr *from, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
{
	if(firewall.closing)
		return KERN_SUCCESS;

#ifdef CLIENT_DEBUG_MESSAGES
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltDataIn(proc_selfpid(), kauth_getuid(), so, ((SocketCookie*)cookie)->sockProtocol, from);
		firewall.Send(message);
		message->Release();
	}
#endif //CLIENT_DEBUG_MESSAGES
	
	return KERN_SUCCESS;
	
	
	SocketCookie *scookie = (SocketCookie*)cookie;
	
	if(scookie == NULL)
		return KERN_SUCCESS;
	
	//int size = 30;
//	sockaddr *sa = (sockaddr*) &buffer;
//	if(KERN_SUCCESS == sock_getsockname(so, sa, 30))
//	{
//		//print name
//		//IOLog("sock address: %s", sa);
//	}
	
//	Message *message = Message::CreateTextFromCookie("data in", (SocketCookie*)cookie);
//	firewall.Send(message);
//	message->Release();
	
//	return KERN_SUCCESS;
	
	//check fo socket changes

	
	if(firewall.rules.IsRulesChanged(scookie->obtainedRuleTime))
	{
		//update rule and set in cookie
		if(scookie->rule != NULL)
		{
			scookie->rule->Release();
			scookie->rule = NULL;
			scookie->obtainedRuleTime = 0;
		}
		
		Rule* rule = firewall.rules.FindRule( 
												  NULL, NULL, 
												  0, 0, 0, 
												  0, 
												  NULL);
		if(rule == NULL)
		{
			scookie->state = SocketCookieStateNOT;
		}
		
	}
	
	switch (scookie->state) 
	{
		case SocketCookieStateNOT:
			//send ask
			scookie->state = SocketCookieStateASK;
			//scookie->aks_rule_time = time();//TODO: insert header
			
		case SocketCookieStateASK:
			scookie->AddDeferredData(1, data, control, flags, from);//TODO: refactor
			return EJUSTRETURN;
		case SocketCookieStateALLOWED:
			return KERN_SUCCESS;
		case SocketCookieStateNOT_ALLOWED:
			return KERN_NO_ACCESS;//KERN_POLICY_LIMIT;//fix return value
		default:
			break;
	}
	
	return -1;
	
}


errno_t	
Firewall::DataOut(void *cookie, socket_t so, const sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
{
//	Message *message = Message::CreateTextFromCookie("data out", (SocketCookie*)cookie);
	if(firewall.closing)
		return KERN_SUCCESS;
	
#ifdef CLIENT_DEBUG_MESSAGES
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltDataOut(proc_selfpid(), kauth_getuid(), so, ((SocketCookie*)cookie)->sockProtocol, to);
		firewall.Send(message);
		message->Release();
	}	
#endif //CLIENT_DEBUG_MESSAGES

	return KERN_SUCCESS;
}


errno_t	
Firewall::ConnectIn(void *cookie, socket_t so, const sockaddr *from)
{
	if(firewall.closing)
		return KERN_SUCCESS;

	SocketCookie *scookie = (SocketCookie*)cookie;

#ifdef CLIENT_DEBUG_MESSAGES
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltConnectIn(proc_selfpid(), kauth_getuid(), so, from);
		firewall.Send(message);
		message->Release();
	}
#endif //CLIENT_DEBUG_MESSAGES
	
	return KERN_SUCCESS;
	
	//only for TCP/IP
	//copy from address or in 
	//scookie->SetFrom(from);//not is bounded

	if(firewall.firewallUp)
	{
		//check is have rule
		//if have apply
		//else allow and ask
		
	}
	
	
	
	if(firewall.countSubscribersForInfoSockets)
	{
		//send message connected
	}
}


errno_t	
Firewall::ConnectOut(void *cookie, socket_t so, const sockaddr *to)
{
//	Message *message = Message::CreateTextFromCookie("connect out", (SocketCookie*)cookie);

	if(firewall.closing)
		return KERN_SUCCESS;

#ifdef CLIENT_DEBUG_MESSAGES
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltConnectOut(proc_selfpid(), kauth_getuid(), so, to);
		firewall.Send(message);
		message->Release();
	}	
#endif //CLIENT_DEBUG_MESSAGES

	return KERN_SUCCESS;
}


errno_t	
Firewall::Bind(void *cookie, socket_t so, const sockaddr *to)
{
//	Message *message = Message::CreateTextFromCookie("bind", (SocketCookie*)cookie);

	if(firewall.closing)
		return KERN_SUCCESS;

#ifdef CLIENT_DEBUG_MESSAGES
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltBind(proc_selfpid(), kauth_getuid(), so, to);
		firewall.Send(message);
		message->Release();
	}
#endif //CLIENT_DEBUG_MESSAGES
	
	if(firewall.firewallUp)
	{
		//check is posible resive connections for that address
		//firewall.rules
	}
	
	return KERN_SUCCESS;
	
	//check is allowed to bind to that address
}


errno_t	
Firewall::SetOption(void *cookie, socket_t so, sockopt_t opt)
{
//	Message *message = Message::CreateTextFromCookie("setoption", (SocketCookie*)cookie);

	if(firewall.closing)
		return KERN_SUCCESS;

#ifdef CLIENT_DEBUG_MESSAGES
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltSetOption(proc_selfpid(), kauth_getuid(), so, opt);
		firewall.Send(message);
		message->Release();
	}	
#endif //CLIENT_DEBUG_MESSAGES

	return KERN_SUCCESS;
}

errno_t	
Firewall::GetOption(void *cookie, socket_t so, sockopt_t opt)
{
//	Message *message = Message::CreateTextFromCookie("getoption", (SocketCookie*)cookie);

	if(firewall.closing)
		return KERN_SUCCESS;

#ifdef CLIENT_DEBUG_MESSAGES
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltGetOption(proc_selfpid(), kauth_getuid(), so, opt);
		firewall.Send(message);
		message->Release();
	}	
#endif //CLIENT_DEBUG_MESSAGES

	return KERN_SUCCESS;
}

errno_t	
Firewall::Listen(void *cookie, socket_t so)
{

//	Message *message = Message::CreateTextFromCookie("listen", (SocketCookie*)cookie);
	
	if(firewall.closing)
		return KERN_SUCCESS;

#ifdef CLIENT_DEBUG_MESSAGES
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltListen(proc_selfpid(), kauth_getuid(), so);
		firewall.Send(message);
		message->Release();
	}	
#endif //CLIENT_DEBUG_MESSAGES

	return KERN_SUCCESS;
	
	//that is for tcp //check is alowed listen
	//if not rule allow and process in accept function
}

errno_t	
Firewall::Ioctl(void *cookie, socket_t so, unsigned long request, const char* argp)
{

//	Message *message = Message::CreateTextFromCookie("ioctl", (SocketCookie*)cookie);
	
	if(firewall.closing)
		return KERN_SUCCESS;

#ifdef CLIENT_DEBUG_MESSAGES
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltIoctl(proc_selfpid(), kauth_getuid(), so, request, argp);
		firewall.Send(message);
		message->Release();
	}
#endif //CLIENT_DEBUG_MESSAGES
	
	return KERN_SUCCESS;
}

errno_t 
Firewall::Accept(void *cookie, socket_t so_listen, socket_t so, const struct sockaddr *local, const struct sockaddr *remote)
{
//	Message *message = Message::CreateTextFromCookie("accept", (SocketCookie*)cookie);

	//TODO: if firewall enabled
	if(firewall.closing)
		return KERN_SUCCESS;

#ifdef CLIENT_DEBUG_MESSAGES
	if(firewall.countSubscribersForDebug)
	{
		Message *message = Message::CreateSfltAccept(proc_selfpid(), kauth_getuid(), so_listen, so, local, remote);
		firewall.Send(message);
		message->Release();
	}
#endif //CLIENT_DEBUG_MESSAGES
	
	return KERN_SUCCESS;
	
	//check if allowed from that remote address
}




bool 
Firewall::Init()
{
	closing = false;
	
	if(socketCookies.Init())
	{	
		if(rules.Init())
		{
			if(applications.Init())
			{	
				if(RegisterSocketFilters())
				{
					if(RegisterKernelControl())
					{
						IOLog("instance created \n");
						return true;
					}
					
					UnregisterSocketFilters();
				}
				applications.Free();
			}
			rules.Free();
			
		}
		socketCookies.Free();
	}
	
	return false;
}

bool
Firewall::Free()
{
	IOLog("firewall instance begin destroyed \n");

	closing = true;
	
	if(!UnregisterKernelControl())
		return false;

	if(socketCookies.HaveAttachedSockets())
		return false;
	
	if(!UnregisterSocketFilters())
		return false;

	IOLog("firewall instance begin destroyed applications \n");
	applications.Free();
	IOSleep(1);

	rules.Free();
	IOSleep(1);
	
	if(!socketCookies.Free())
		return false;

	IOLog("firewall instance destroyed \n");
	
	return true;
}


#pragma mark kernel control

kern_ctl_reg 
Firewall::kernelControlRegistration = 
{
MYBUNDLEID,								/* use a reverse dns name which includes a name unique to your company */
0,										/* set to 0 for dynamically assigned control ID - CTL_FLAG_REG_ID_UNIT not set */
0,										/* ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set */
0,//CTL_FLAG_PRIVILEGED, //removed for test										/* privileged access required to access this filter */
(8 * 1024),								/* Override receive buffer size */
(8 * 1024),								/* Override receive buffer size */
KcConnect,								/* Called when a connection request is accepted */
KcDisconnect,							/* called when a connection becomes disconnected */
KcSend,									/* ctl_send_func - handles data sent from the client to kernel control  */
KcSetSocketOption,						/* called when the user process makes the setsockopt call */
KcGetSocketOption						/* called when the user process makes the getsockopt call */
};

bool 
Firewall::RegisterKernelControl()
{
	if((this->lockClientsQueue = IOLockAlloc()))
	{
		if(!ctl_register(&kernelControlRegistration, &kernelControlReference))
			return true;
	
		IOLockFree(this->lockClientsQueue);
		this->lockClientsQueue = NULL;
	}
	return false;
}

bool Firewall::UnregisterKernelControl()
{
	if(lockClientsQueue == NULL)
		return true;

	Message *message = Message::CreateFirewallClosing();
	if(message)
	{
		Send(message);
		message->Release();
	}
	
	for (int i = 2; i; i--) 
	{
		bool clientsExits = false;
		IOLockLock(this->lockClientsQueue);
		clientsExits = this->clients == NULL;
		IOLockUnlock(this->lockClientsQueue);
		
		if(clientsExits)
			goto deregister;
		
		IOSleep(200);
	}
	return false;
	
deregister:
	if(kernelControlReference && ctl_deregister(kernelControlReference))	
		return false;
	
	kernelControlReference = NULL;
	
	if(this->lockClientsQueue)
	{
		IOLockFree(this->lockClientsQueue);
		this->lockClientsQueue = NULL;
	}
	return true;
}

void 
Firewall::Send(Message *message)
{
	if(!this->lockClientsQueue)
		return;
	
	IOLockLock(this->lockClientsQueue);
	
	for(Client *client = this->clients; client; client = client->next)
		client->Send(message);
	
	IOLockUnlock(this->lockClientsQueue);
}

errno_t 
Firewall::KcConnect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo)
{
	if(firewall.closing )
		return KERN_FAILURE;
	
	Client *client = new Client();
	if(!client)
		return ENOMEM;
	
	if(client->InitWithClient(kctlref, sac->sc_unit) == false)
	{
		delete client;
		return ENOMEM;
	}
	
	IOLockLock(firewall.lockClientsQueue);
	
	client->next = firewall.clients;
	firewall.clients = client;

#ifdef CLIENT_DEBUG_MESSAGES
	OSIncrementAtomic(&firewall.countSubscribersForDebug);//TODO: debug
#endif //CLIENT_DEBUG_MESSAGES
	
	IOLockUnlock(firewall.lockClientsQueue);
	
	*unitinfo = client;
	return KERN_SUCCESS;
}

errno_t 
Firewall::KcDisconnect(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo)
{
	Client *client = (Client*)unitinfo;
	if(client == NULL)
		return KERN_SUCCESS;
	
	IOLockLock(firewall.lockClientsQueue);
	
	Client *prev = NULL;
	Client *curr = firewall.clients;
	
	while(curr)
	{
		if(curr == client)
		{
			if(prev)
				prev->next = curr->next;
			else
				firewall.clients = curr->next;
			
			curr->CloseSignal();
			//update counts of listen etc...
			if(curr->registredMessageClases & MessageClassProviderOfRules)
				OSDecrementAtomic(&firewall.countSubscribersAsaProviderOfRules);

			if(curr->registredMessageClases & MessageClassInfoRules)
				OSDecrementAtomic(&firewall.countSubscribersForInfoRules);
			
			if(curr->registredMessageClases & MessageClassInfoSockets)
				OSDecrementAtomic(&firewall.countSubscribersForInfoSockets);

#ifdef CLIENT_DEBUG_MESSAGES
			if(curr->registredMessageClases & MessageClassCommon)
				OSDecrementAtomic(&firewall.countSubscribersForDebug);
#endif //CLIENT_DEBUG_MESSAGES

			curr->Release();
			break;
		}
		
		prev = curr;
		curr = curr->next;
	}	
	
	IOLockUnlock(firewall.lockClientsQueue);
	
	return KERN_SUCCESS;
}

errno_t 
Firewall::KcSend(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags)
{	
	Client *client = (Client*)unitinfo;
	
	if(firewall.closing || client == NULL)
		return KERN_TERMINATED;
	
	UInt32 currentPosition = 0;
	
	size_t dataSize= mbuf_len(m);
	RawMessageClientAction *message = (RawMessageClientAction*) mbuf_data(m);
	
	while(currentPosition < dataSize)
	{
		switch (message->type)
		{
			case MessageTypeDeleteRule:
				{
					RawMessageDeleteRule *rawMessageDeleteRule = (RawMessageDeleteRule*) message;
					
					Message* responce = Message::CreateRuleDeleted(client->unit, message->messageId, 0, rawMessageDeleteRule->ruleId);
					if(responce == NULL)
						break;

					RawMessageRuleDeleted *rawResponce = (RawMessageRuleDeleted*)&responce->raw;
					switch(firewall.rules.DeleteRule(rawMessageDeleteRule->ruleId))
					{
						case 0://OK
							firewall.Send(responce);
							break;
						case 1://not exist
							rawResponce->actionState = -1;
							client->Send(responce);
							break;
					}
					
					responce->Release();
				}
				break;
				
			case MessageTypeAddRule:
				{
					RawMessageAddRule* rawMessageAddRule = (RawMessageAddRule*) message;
					
					//TODO: refactor message
					Message* responce = Message::CreateRuleAdded(client->unit, rawMessageAddRule->id, 0, 0);
					if(responce == NULL)
						break;
					
					RawMessageRuleAdded* rawResponce = (RawMessageRuleAdded*)&responce->raw;
					Rule *rule = NULL;
					switch(firewall.rules.AddRule(rawMessageAddRule, &rule))
					{
						case -1://memory error
							rawResponce->actionState = -1;
							client->Send(responce);
						   break;
						case 0://ok
							//TODO: fill new rule data
							firewall.Send(responce);
						   break;
						case 1://already exist
							rawResponce->actionState = 1;
							client->Send(responce);
						   break;
					}
						   
					if(rule)
						   rule->Release();
					
					responce->Release();
				}
				break;
				
			case MessageTypeActivateRule:
				{
					RawMessageActivateRule *rawMessage = (RawMessageActivateRule*)message;

					Message *responce = Message::CreateRuleActivated(client->unit, rawMessage->messageId, 0, rawMessage->ruleId);
					if(responce == NULL)
						break;

					RawMessageRuleActivated *rawResponce = (RawMessageRuleActivated*)&responce->raw;
					switch(firewall.rules.ActivateRule(rawMessage->ruleId))
					{
						case -1://not exist
							rawResponce->actionState = -1;
							client->Send(responce);
							break;

						case 0://ok
							rawResponce->actionState = 0;
							firewall.Send(responce);
						   break;

						case 1://already activated
							rawResponce->actionState = 1;
							client->Send(responce);
						   break;
					}

					responce->Release();
				}
				break;
				
			case MessageTypeDeactivateRule:
				{
					RawMessageDeactivateRule *rawMessage = (RawMessageDeactivateRule*)message;

					Message *responce = Message::CreateRuleDeactivated(client->unit, rawMessage->messageId, 0, rawMessage->ruleId);
					if(responce == NULL)
						break;

					RawMessageRuleDeactivated *rawResponce = (RawMessageRuleDeactivated*)&responce->raw;
					switch(firewall.rules.DeactivateRule(rawMessage->ruleId))
					{
						case -1://not exist
							rawResponce->actionState = -1;
							client->Send(responce);
							break;

						case 0://ok
							rawResponce->actionState = 0;
							firewall.Send(responce);
							break;

						case 1://already deactivated
							rawResponce->actionState = 1;
							client->Send(responce);
							break;
					}

					responce->Release();
				}
				break;
				
			case MessageTypeActivateFirewall:
				{
					Message* responce = Message::CreateFirewallActivated(client->unit, message->messageId, 0);
					if(responce == NULL) break;
					RawMessageFirewallActivated* rawResponce = (RawMessageFirewallActivated*)&responce->raw;
					
					if(firewall.firewallUp == false)
					{
						firewall.firewallUp = true;
						firewall.Send(responce);
						
					}
					else
					{
						rawResponce->actionState = 1;
						client->Send(responce);
					}
					
					responce->Release();
				}
				break;
				
			case MessageTypeDeactivateFirewall:
				{
					Message* responce = Message::CreateFirewallDeactivated(client->unit, message->messageId, 0);
					if(responce == NULL) break;
					RawMessageFirewallDeactivated* rawResponce = (RawMessageFirewallDeactivated*)&responce->raw;

					if(firewall.firewallUp == true)
					{
						firewall.firewallUp = false;
						firewall.Send(responce);
					}
					else
					{
						rawResponce->actionState = 1;
						client->Send(responce);
					}
					
					responce->Release();
				}
				break;
				
			case MessageTypeSubscribeAsaProviderOfRules:
				{
					Message* responce = Message::CreateClientSubscribedAsaProviderOfRules(client->unit, message->messageId, 0);
					if(responce == NULL) break;
					RawMessageClientSubscribedAsaProviderOfRules *rawResponce = (RawMessageClientSubscribedAsaProviderOfRules*)&responce->raw;
					
					if(client->RegisterMessageClasses(MessageClassProviderOfRules))
						OSIncrementAtomic(&firewall.countSubscribersAsaProviderOfRules);
					else
						rawResponce->actionState = 1;
					
					client->Send(responce);
					responce->Release();
				}
				break;
				
			case MessageTypeUnsubscribeAsaProviderOfRules:
				{
					Message* responce = Message::CreateClientUnsubscribedAsaProviderOfRules(client->unit, message->messageId, 0);
					if(responce == NULL) break;
					RawMessageClientUnsubscribedAsaProviderOfRules* rawResponce = (RawMessageClientUnsubscribedAsaProviderOfRules*)&responce->raw;
					
					if(client->UnregisterMessageClasses(MessageClassProviderOfRules))
						OSDecrementAtomic(&firewall.countSubscribersAsaProviderOfRules);
					else
						rawResponce->actionState = 1;
					
					client->Send(responce);
					responce->Release();
				}
				break;
				
			case MessageTypeSubscribeToInfoRules:
				{
					Message* responce = Message::CreateClientSubscribedToInfoRules(client->unit, message->messageId, 0);
					if(responce == NULL) break;
					RawMessageClientSubscribedToInfoRules* rawResponce = (RawMessageClientSubscribedToInfoRules*)&responce->raw;
					
					if(client->RegisterMessageClasses(MessageClassInfoRules))
						OSIncrementAtomic(&firewall.countSubscribersForInfoRules);
					else
						rawResponce->actionState = 1;
					
					client->Send(responce);
					responce->Release();
				}
				break;

			case MessageTypeUnsubscribeFromInfoRules:
				{
					Message* responce = Message::CreateClientUnsubscribedFromInfoRules(client->unit, message->messageId, 0);
					if(responce == NULL)
						break;

					RawMessageClientUnsubscribedFromInfoRules* rawResponce = (RawMessageClientUnsubscribedFromInfoRules*)&responce->raw;
					
					if(client->UnregisterMessageClasses(MessageClassInfoRules))
						OSDecrementAtomic(&firewall.countSubscribersForInfoRules);
					else
						rawResponce->actionState = 1;

					client->Send(responce);
					responce->Release();
				}
				break;
				
			case MessageTypeSubscribeToInfoSockets:
				{
					Message* responce = Message::CreateClientSubscribedToInfoSockets(client->unit, message->messageId, 0);
					if(responce == NULL) break;
					RawMessageClientSubscribedToInfoSockets *rawResponce = (RawMessageClientSubscribedToInfoSockets*)&responce->raw;
					
					if(client->RegisterMessageClasses(MessageClassInfoSockets))
						OSIncrementAtomic(&firewall.countSubscribersForInfoSockets);
					else
						rawResponce->actionState = 1;

					client->Send(responce);
					responce->Release();
				}
				break;
				
			case MessageTypeUnsubscribeFromInfoSockets:
				{
					Message* responce = Message::CreateClientUnsubscribedFromInfoSockets(client->unit, message->messageId, 0);
					if(responce == NULL) break;
					RawMessageClientUnsubscribedFromInfoSockets* rawResponce = (RawMessageClientUnsubscribedFromInfoSockets*)&responce->raw;
					
					if(client->UnregisterMessageClasses(MessageClassInfoSockets))
						OSDecrementAtomic(&firewall.countSubscribersForInfoSockets);
					else
						rawResponce->actionState = 1;
					
					client->Send(responce);
					responce->Release();
				}
				break;
		}
		
		currentPosition += message->size;
		message = (RawMessageClientAction*)((char*)message + message->size);
	}
	
	return KERN_SUCCESS;
}

errno_t 
Firewall::KcSetSocketOption(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len)
{
	//register for info and ui provider
	return KERN_SUCCESS;
}

errno_t 
Firewall::KcGetSocketOption(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len)
{
	return KERN_SUCCESS;
}
