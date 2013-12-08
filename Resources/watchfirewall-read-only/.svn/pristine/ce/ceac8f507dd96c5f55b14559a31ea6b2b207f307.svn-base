#ifndef WATCH_APPLICATION_H
#define WATCH_APPLICATION_H

#include <libkern/c++/OSString.h>
#include <IOKit/IOLocks.h>
#include <sys/kauth.h>
#include <sys/vnode.h>
#include <libkern/crypto/sha1.h>

#include "simpleBase.h"

class __attribute__((visibility("hidden"))) Application: public SimpleBase
{
public:
	pid_t pid;
	pid_t p_pid;
	uid_t uid;
	gid_t gid;
	OSString *processName;
	OSString *filePath;

	timespec createTime;
	timespec modifyTime;

	UInt64 dataSize; 
	
	Application *prev;
	Application *next;

	virtual void Free()
	{
		if(filePath)
			filePath->release();
		
		if(processName)
			processName->release();
		
		SimpleBase::Free();
	}
};

class __attribute__((visibility("hidden"))) Applications
{
public:
	
	Application *head;
	IOLock *lock;
	IOLock *lockRoutine;
	IOThread thread;
	SInt32 closing;
	SInt32 countProcessesToCheck;
	
	kauth_listener_t processListener;
	
public:
	bool Init();
	void Free();

	Application* Get(); 
	Application* Add(kauth_cred_t cred, vnode_t vnode, const char *filePath);
	void		 AddLocked(kauth_cred_t cred, vnode_t vnode, const char *filePath);

	static void CheckIsLiveRoutine(void *arg, wait_result_t waitResult);
	static int CallbackProcessListener
	(
	 kauth_cred_t    credential,
	 void *          idata,
	 kauth_action_t  action,
	 uintptr_t       arg0,
	 uintptr_t       arg1,
	 uintptr_t       arg2,
	 uintptr_t       arg3
	 );
	
public:
	
	Application* Remove(Application* application)
	{
		if(application->prev)
			application->prev->next = application->next;
		else
			head = application->next;
		
		if(application->next)
			application->next->prev = application->prev;
		
		return application;
	}
};

#endif WATCH_APPLICATION_H

