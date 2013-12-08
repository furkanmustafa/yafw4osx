#include "cookie.h"
#include <sys/proc.h>

mbuf_tag_id_t SocketCookies::mbufTagId;

//used only if exit extension
bool
SocketCookie::IsValid()
{
	//check socket
	
	//check last pid used
	proc_t p;
	p = proc_find(this->application->pid);
	if (p)
	{
		proc_rele(p);
		return true;
	}
	return false;
}

bool 
SocketCookie::SetFrom(const sockaddr *sa)
{
	if(this->from)
	{
		delete this->from;
		this->from = NULL;
	}
	
	this->from = (sockaddr*)new UInt8[sa->sa_len];
	if(this->from == NULL)
		return false;
	
	memcpy(this->from, sa, sa->sa_len);
	
	return true;
}

bool 
SocketCookie::SetTo(const sockaddr *sa)
{
	if(this->to)
	{
		delete this->to;
		this->to = NULL;
	}
	
	this->to = (sockaddr*)new UInt8[sa->sa_len];
	if(this->to == NULL)
		return false;
	
	memcpy(this->to, sa, sa->sa_len);
	
	return true;
}


bool 
SocketCookie::AddDeferredData(bool direction, mbuf_t* data, mbuf_t* control, sflt_data_flag_t flags, const sockaddr *socketAddress)
{
	DeferredData *deferredData = new(socketAddress->sa_len) DeferredData;
	if(deferredData)
	{
		deferredData->data = data ? *data : NULL;
		deferredData->control = control ? *control : NULL;
		deferredData->flags = flags;
		
		if(socketAddress)
			memcpy(&deferredData->socketAddress, socketAddress, socketAddress->sa_len);
		else
			deferredData->socketAddress = 0;
		
		if(deferredDataLast)
		{
			deferredDataLast->next = deferredData;
			deferredDataLast = deferredData;
		}
		else
		{
			deferredDataHead = deferredData;
			deferredDataLast = deferredData;
		}
		
		return true;
	}
	return false;
}

bool 
SocketCookie::ClearDeferredData()
{
	while (deferredDataHead) 
	{
		mbuf_freem(deferredDataHead->data);
		mbuf_freem(deferredDataHead->control);
		
		DeferredData *old = deferredDataHead;
		deferredDataHead = deferredDataHead->next;
		delete old;
	}
	
	deferredDataLast = NULL;
	return true;
}

bool 
SocketCookie::SendDeferredData()
{
	while (deferredDataHead) 
	{
		if(deferredDataHead->direction)
		{
			if(sock_inject_data_in(socket, deferredDataHead->GetSockAddress(), deferredDataHead->data, deferredDataHead->control, deferredDataHead->flags))
			{
				mbuf_freem(deferredDataHead->data);
				mbuf_freem(deferredDataHead->control);
			}
		}
		else
		{
			sock_inject_data_out(socket, deferredDataHead->GetSockAddress(), deferredDataHead->data, deferredDataHead->control, deferredDataHead->flags);
		}
		
		DeferredData *old = deferredDataHead;
		deferredDataHead = deferredDataHead->next;
		delete old;
	}
	
	deferredDataLast = NULL;
	return true;
}

