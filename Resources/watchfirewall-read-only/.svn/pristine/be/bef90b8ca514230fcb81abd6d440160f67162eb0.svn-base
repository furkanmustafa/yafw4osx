#ifndef SERVER_CONNECTION_H
#define SERVER_CONNECTION_H

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/kern_control.h>
#include <pthread.h>

#include "bundleid.h"
#include "messageType.h"

class ServerConnection;

typedef void (*MessageReceiveDelegate)(const RawMessageBase* message);
typedef void (*ServerConnectionClosed)(const ServerConnection* connection);

class ServerConnection 
{
public :
	bool Open(MessageReceiveDelegate receiveDelegate, ServerConnectionClosed closedDelegate);
	bool Close();
	
	int SendMessage(RawMessageBase *message);
	int	Send( const void* data, size_t size);
	
	static void* ReceiveThread(void* object);
	
	ServerConnection()
	{
		gSocket = -1;
		receiveThread = NULL;
		receiveDelegate = NULL;
		closedDelegate = NULL;
		pthread_mutex_init(&syncMutex, NULL);// = PTHREAD_MUTEX_INITIALIZER;
	}
	
	~ServerConnection()
	{
		Close();
		pthread_mutex_destroy(&syncMutex); 
	}
	
protected:
private:
	
	sockaddr_ctl	sc;
	socklen_t		size;
	ctl_info		m_ctl_info;
	
	pthread_mutex_t syncMutex;
	pthread_t		receiveThread;
	MessageReceiveDelegate receiveDelegate;
	ServerConnectionClosed closedDelegate;

public:

	int			gSocket;// = -1;
	
};

#endif /* SERVER_CONNECTION_H */
