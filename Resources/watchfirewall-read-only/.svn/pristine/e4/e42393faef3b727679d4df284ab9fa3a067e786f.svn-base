#ifndef WATCH_COOKIE_H
#define WATCH_COOKIE_H

#include <sys/kpi_socketfilter.h>
#include <sys/mbuf.h>

#include "rule.h"
#include "application.h"


enum /*__attribute__((visibility("hidden")))*/ SocketCookieState
{
	SocketCookieStateNOT = 1,	
	SocketCookieStateASK = 2,	
	SocketCookieStateALLOWED = 4,	
	SocketCookieStateNOT_ALLOWED = 8
};

class __attribute__((visibility("hidden"))) DeferredData
{
public:
	mbuf_t data;
	mbuf_t control;
	sflt_data_flag_t flags;
	bool direction; //true out, false in
	
	DeferredData *next;

	char socketAddress;
	
	inline void *operator new(size_t size, UInt16 additionalSize){ return ::new char[additionalSize + size]; }
	sockaddr* GetSockAddress(){ return socketAddress ? (sockaddr*)&socketAddress : NULL; }

};

class __attribute__((visibility("hidden"))) SocketCookie
{
public:
	Application* application;
	SocketCookieState state;
	socket_t socket;
	UInt16 sockDomain;
	UInt16 sockType;
	UInt16 sockProtocol;	
	
	UInt64 aksRuelTime;
	UInt64 obtainedRuleTime;
	
	DeferredData *deferredDataHead;
	DeferredData *deferredDataLast;
	
	Rule *rule;
	
	struct sockaddr *from;
	struct sockaddr *to;
	
	SocketCookie *prev;
	SocketCookie *next;
	
public:
	bool IsValid();
	
	void SetSocket(socket_t socket)
	{
		int domain;
		int type;
		int protocol;
		sock_gettype(socket, &domain, &type, &protocol);
		
		this->sockDomain = domain;
		this->sockType = type;
		this->sockProtocol = protocol;
		this->socket = socket;
	}
	
	void Free()
	{
		//TODO: free deferred data
		ClearDeferredData();
		
		if(rule)
			rule->Release();
		
		if(application)
			application->Release();
		
		if(from)
			delete from;
		
		if(to)
			delete to;
		
		delete this;
		
	}
	
	bool SetFrom(const sockaddr *sa);
	bool SetTo(const sockaddr *sa);
	
	bool AddDeferredData(bool direction, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags, const sockaddr *sa);
	bool ClearDeferredData();
	bool SendDeferredData();
	
	
};

class __attribute__((visibility("hidden"))) SocketCookies
{
public:
	IOLock *lock;
	SocketCookie *socketCookies;
	static mbuf_tag_id_t mbufTagId;
	
	int countAttachedCookies;
	
public:
	SocketCookie * Remove(SocketCookie *cookie)
	{
		IOLockLock(lock);
		countAttachedCookies--;
		IOLog("countof attached cookies : %d\n", countAttachedCookies);
		
		if(cookie->prev)
			cookie->prev->next = cookie->next;
		else
			socketCookies = cookie->next;
		
		if(cookie->next)
			cookie->next->prev = cookie->prev;
		
		IOLockUnlock(lock);
		
		return cookie;
	}
	
	void Add(SocketCookie *cookie)
	{
		IOLockLock(lock);
		countAttachedCookies++;
		IOLog("countof attached cookies : %d\n", countAttachedCookies);
		cookie->next = socketCookies;
		socketCookies = cookie;
		
		if(cookie->next)
			cookie->next->prev = cookie; 
		
		IOLockUnlock(lock);
	}
	
	bool Init()
	{
		countAttachedCookies = 0;
		if(lock == NULL)
		{
			IOLog("create socket cookie lock\n");
			lock = IOLockAlloc();
			if(lock)
			{
				if(mbuf_tag_id_find(MYBUNDLEID , &mbufTagId) == KERN_SUCCESS)
					return true;
			}
			IOLockFree(lock);			
		}
		
		return false;
	}
	
	bool Free()
	{
		if(!HaveAttachedSockets())
		{
			IOLockFree(lock);
			lock = NULL;
			return true;
		}
		
		return false;
	}
	
	bool HaveAttachedSockets()
	{
		bool result = false;
		IOLockLock(lock);
		result = (socketCookies != NULL);
		IOLockUnlock(lock);
		
		return result;
	}
	
	static bool PrependMbufHeader(mbuf_t *data, size_t pkt_len)
	{
		mbuf_t new_hdr;
		
		if (KERN_SUCCESS == mbuf_gethdr(MBUF_WAITOK, MBUF_TYPE_DATA, &new_hdr))
		{
			mbuf_setnext(new_hdr, *data);
			mbuf_setnextpkt(new_hdr, mbuf_nextpkt(*data));
			mbuf_pkthdr_setlen(new_hdr, pkt_len);
			mbuf_setlen(new_hdr, 0);
			mbuf_pkthdr_setrcvif(*data, NULL);
			
			*data = new_hdr;
			return true;
		}
		
		return false;
	}
	
	
	static bool	CheckTag(mbuf_t *m, int value)
	{
		errno_t	status;
		int		*tagReference;
		size_t	len;
		
		status = mbuf_tag_find(*m, mbufTagId, 1, &len, (void**)&tagReference);
		if ((status == 0)  && (len == sizeof(value)) && (*tagReference == value))
			return true;
		
		return false;
	}
	
	static bool	SetTag(mbuf_t *data, int value)
	{	
		int		*tagReference = NULL;
		
		switch(mbuf_tag_allocate(*data, mbufTagId, 1, sizeof(value), MBUF_WAITOK, (void**)&tagReference))
		{
			case KERN_SUCCESS:
			{
				*tagReference = value;
				return true;
			}
				
			case EINVAL:
			{			
				mbuf_flags_t flags = mbuf_flags(*data);
				if ((flags & MBUF_PKTHDR) == 0)
				{
					size_t			totalbytes = 0;
					
					for (mbuf_t	m = *data; m; m = mbuf_next(m))
						totalbytes += mbuf_len(m);
					
					if (PrependMbufHeader(data, totalbytes))
					{
						if(mbuf_tag_allocate(*data, mbufTagId, 1, sizeof(value), MBUF_WAITOK, (void**)&tagReference) == KERN_SUCCESS)						
						{
							*tagReference = value;
							return true;
						}
					}
				}
			}
				
			default:
				return false;
		}	
	}
	
};


#endif

