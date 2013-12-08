
#include "ServerConnection.h"


#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

bool ServerConnection::Open(MessageReceiveDelegate receiveDelegate, ServerConnectionClosed closedDelegate)
{
	bool result = false;
	pthread_mutex_lock(&syncMutex);
	
	if((gSocket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) > 0)
	{
		bzero(&m_ctl_info, sizeof(struct ctl_info));
		strcpy(m_ctl_info.ctl_name, MYBUNDLEID);
		
		if (ioctl(gSocket, CTLIOCGINFO, &m_ctl_info) != -1)
		{
			bzero(&sc, sizeof(struct sockaddr_ctl));
			sc.sc_len = sizeof(struct sockaddr_ctl);
			sc.sc_family = AF_SYSTEM;
			sc.ss_sysaddr = SYSPROTO_CONTROL;
			sc.sc_id = m_ctl_info.ctl_id;
			sc.sc_unit = 0;
			
			this->receiveDelegate = receiveDelegate;
			this->closedDelegate = closedDelegate;
			
			if(!connect(gSocket, (struct sockaddr *)&sc, sizeof(struct sockaddr_ctl)))
			{
				pthread_attr_t  attr;
				if(!pthread_attr_init(&attr))
				{
					pthread_attr_setstacksize(&attr, 10*1024);
					int relust = pthread_create(&receiveThread, &attr, &ReceiveThread, this);
				
					pthread_attr_destroy(&attr);
					if(result == 0)
					{
						result = true;
						goto unlock;
					}
				}
			}
		}
		
		close(gSocket);
		gSocket = -1;
	}
	
unlock:
	pthread_mutex_unlock(&syncMutex);
	return result;
}

bool ServerConnection::Close()
{
	bool result;
	pthread_mutex_lock(&syncMutex);
	result = (gSocket > 0 && !close(gSocket));
	pthread_mutex_unlock(&syncMutex);
	return result;
}

int ServerConnection::SendMessage(RawMessageBase *message)
{
	if(message)
		return Send(message, message->size);
	
	return 0;
}

int ServerConnection::Send( const void* data, size_t size)
{	
	return send(this->gSocket, data, size, 0);	
}

void* ServerConnection::ReceiveThread(void* object)
{
	ServerConnection* sc = (ServerConnection*)object;
	char buffer[8*1024];
	int n;
	while ((n = recv(sc->gSocket, buffer, 8 * 1024 , 0)) != 0)
	{
		if(n == -1)
			break;
		
		for(int k = 0; k < n;  )
		{
			RawMessageBase *message = (RawMessageBase*)(buffer + k);
			if(sc->receiveDelegate) sc->receiveDelegate(message);
			if(message->type == MessageTypeFirewallClosing)	goto close;

			k += message->size;
		}
	}
	
close:;

	pthread_mutex_lock(&sc->syncMutex);
	if(sc->gSocket > 0)
		close(sc->gSocket);

	sc->gSocket = -1;
	sc->receiveThread = NULL;
	
	if(sc->closedDelegate)
		sc->closedDelegate(sc);
	
	pthread_mutex_unlock(&sc->syncMutex);
	
	return 0;
}
