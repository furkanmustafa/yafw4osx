#ifndef WATCH_RULE_H
#define WATCH_RULE_H


#include <sys/param.h>
#include <sys/socket.h>
#include <libkern/c++/OSString.h>
#include <IOKit/IOLib.h>

#include "bundleid.h"
#include "simpleBase.h"
#include "messageType.h"


enum RuleState 
{
	RuleStateActive = 1,
	RuleStateInactive = 2,
	RuleStateDeleted = 3
};

class __attribute__((visibility("hidden"))) Rule: public SimpleBase
{
	UInt32 id;
	timespec obtainedTime;
	
	OSString *processName;
	OSString *filePath;

	timespec fileCreateTime;
	timespec fileModifyTime;

	UInt64 fileDataSize; 

	UInt8 ingnoreFileChanges;
	
	UInt16 sockDomain;//0 for all
	UInt16 sockType;//0 for all
	UInt16 sockProtocol;// 0 for all
	SockAddress* fromSockAddress;// 0 for all
	SockAddress* toSockAddress;//
	
	
	UInt8 direction;//0 both. 1 incoming, 2 outgoing
	UInt8 allow;//0 deny, 1 allow
	
	UInt8 state;
	
	IOLock *lock;

private:
	Rule* prev;
	Rule* next;
	
public:
	bool Init(RawMessageAddRule *message);
	virtual void Free();
	
	bool IsApplicable();
	
	int Compare(Rule *toRule);
	
	friend class Rules;
};

class __attribute__((visibility("hidden"))) Rules 
{
public:
	Rule *root;
		
	UInt64 lastChangedTime; 
	IOLock *lock;
	//sorted by process_name , ...
	bool Init()
	{ 
		lastChangedTime = 0;
		lock = IOLockAlloc();
		if(!lock)
			return false;
		
		return true; 
	}
	
	void Free()
	{
		if(lock)
		{
			IOLockLock(lock);

			while(root)
				RemoveFromChain(root)->Release();

			IOLockUnlock(lock);
			
			IOLockFree(lock);
			lock = NULL;
		}
	}
	
	Rule* RemoveFromChain(Rule *rule)
	{
		if(rule->prev)
			rule->prev->next = rule->next;
		else
			root = rule->next;
		
		if(rule->next)
			rule->next->prev = rule->prev;
		
		rule->prev = rule->next = NULL;
		
		return rule;
		
	}

	bool IsRulesChanged(UInt64 fromTime) { return lastChangedTime > fromTime;}
	Rule* FindRule(const OSString* process_name, const OSString* process_path, 
				   UInt16 sock_famely, UInt16 socket_type, UInt16 sock_protocol, 
				   UInt8 direction, struct sockaddr *sockaddres );
	
	
	int AddRule(RawMessageAddRule *messageRule, Rule** rule);
	int DeleteRule(UInt32 ruleId);
	int ActivateRule(UInt32 ruleId);
	int DeactivateRule(UInt32 ruleId);
	
};

#endif

