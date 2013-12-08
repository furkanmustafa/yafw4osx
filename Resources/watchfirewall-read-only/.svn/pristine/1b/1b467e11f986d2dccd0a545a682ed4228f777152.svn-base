#ifndef WATCH_CLIENT_H
#define WATCH_CLIENT_H

#include <libkern/OSTypes.h>
#include <libkern/c++/OSObject.h>
#include <sys/kern_control.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOLib.h>

#include <sys/queue.h>
#include <sys/sys_domain.h>

#include "messages.h"
#include "simpleBase.h"

struct __attribute__((visibility("hidden"))) ClientMessageNode 
{
	Message *message;
	ClientMessageNode *next;
};

class __attribute__((visibility("hidden"))) Client : public SimpleBase
{
protected:
	static void ClearQueue(ClientMessageNode *root);

public:
	kern_ctl_ref kernelKontrolReference;
	UInt32 unit;
	
	volatile UInt32 registredMessageClases __attribute__ ((aligned (4)));
	
	volatile SInt32 exitState;
	IOSimpleLock *lockQueue;
	IOLock *lockWorkThread;
	thread_t thread;
	
	ClientMessageNode *messageQueueHead;
	ClientMessageNode *messageQueueLast;
	
	Client* next;
	
	bool InitWithClient(kern_ctl_ref kernelKontrolReference, UInt32 unit);
	
	bool RegisterMessageClasses(UInt16 classes);
	bool UnregisterMessageClasses(UInt16 classes);
	
	virtual void Free();
	void CloseSignal();

	void Send(Message* message);
	static void SendThread(void* arg, wait_result_t waitResult);
	
	//void ShowSocketStates();

};

#endif WATCH_CLIENT_H

