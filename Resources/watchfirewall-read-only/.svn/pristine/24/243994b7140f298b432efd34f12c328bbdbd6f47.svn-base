#include <string.h>
#include <kern/clock.h>
#include <sys/vnode_if.h>


#include "rule.h"

bool 
Rule::Init(RawMessageAddRule *message)
{	
	if(message)
	{
		if((this->processName = OSString::withCString(message->GetProcessName())))
		{
			if((this->filePath = OSString::withCString(message->GetFilePath())))
			{
				SockAddress *t = (SockAddress*)message->GetFromSockAddress();
				if(t)
				{
					this->fromSockAddress = (SockAddress*)new char[t->len];
					if(this->fromSockAddress)
					{
						memcpy(this->fromSockAddress, t, t->len);
					}
				}

				if((t && this->fromSockAddress) || !t)
				{
					this->id = message->id;
					
					this->sockDomain = message->sockDomain;
					this->sockType = message->sockType;
					this->sockProtocol = message->sockProtocol;
					
					
					this->direction = message->direction;
					this->allow = message->allow;
					this->state = message->state;
					this->references = 1;
					
					return true;
				}
				this->filePath->release();
			}
			this->processName->release();
		}
	}
	
	return false;
}

void 
Rule::Free()
{
	if(this->filePath)
		this->filePath->release();
	
	if(this->processName)
		this->processName->release();
	
	if(this->fromSockAddress)
		delete fromSockAddress;
	
	SimpleBase::Free();
}

int 
Rule::Compare(Rule *toRule)
{
	int result = 0;
	result = strcmp(this->processName->getCStringNoCopy(), toRule->processName->getCStringNoCopy());
	if(result != 0)
		return result;
	
	result = strcmp(this->filePath->getCStringNoCopy(), toRule->filePath->getCStringNoCopy());
	if(result != 0)
		return result;
	
	result = (int)this->sockDomain - toRule->sockDomain;
	if(result != 0)
		return result;
	
	result = (int)this->sockType - toRule->sockType;
	if(result != 0)
		return result;
	
	result = (int)this->sockProtocol - toRule->sockProtocol;
	if(result != 0)
		return result;
	
	//get sock address comparer
	
	result = (int)this->direction - toRule->direction;
	if(result != 0)
		return result;
	
	result = (int)this->allow - toRule->allow;
	
	return result;
}

Rule* 
Rules::FindRule(const OSString* processName, const OSString* filePath, 
			   UInt16 sockDomain, UInt16 sockType, UInt16 sockProtocol, 
			   UInt8 direction, struct sockaddr *sockaddres )
{
	IOLockLock(lock);
	Rule* current = this->root;
	//bool beIdentical=true;
	while (current)
	{
		if(current->processName->getLength() == 0 || current->processName->isEqualTo(processName))
		{
			if(current->filePath->getLength() == 0 || current->filePath->isEqualTo(filePath))
			{
				if(current->sockDomain == 0 || current->sockDomain == sockDomain)
				{
					if(current->sockType == 0 || current->sockType == sockType)
					{
						if(current->sockProtocol == 0 || current->sockProtocol == sockProtocol)
						{
							if((current->direction & direction) > 0)
							{
								//skip sockaddress
								
								current->Retain();
								break;
							}
							
						}
					}
				}
			}
		}
		current = current->next;
	}
	
//unlock:
	IOLockUnlock(lock);
	return current;
}

int 
Rules::AddRule(RawMessageAddRule *messageRule, Rule** rule)
{
	*rule = NULL;
	int result;
	Rule *workRule = new Rule();
	if(workRule == NULL)
	{
		IOLog("can't create Rule");
		return -1;
	}
	
	if(workRule->Init(messageRule) == false)
	{
		delete workRule;
		return -1;
	}
	
	IOLockLock(lock);
	
	Rule *prev = NULL;
	Rule* current = this->root;
	while (current)
	{
		result = workRule->Compare(current);
		if(result == 0)
		{
			workRule->Release();
			current->Retain();
			*rule = current;
			result = 1;//rule exist
			break;
		}
		if(result > 0)
		{
			//insert before c
			workRule->next = current;
			workRule->prev = current->prev;

			current->prev = workRule;
			
			if(workRule->prev)
				workRule->prev->next = workRule;
			else
				this->root = workRule;//prev is root, replace
			
			//get rule id
			workRule->Retain();
			*rule = workRule;
			result = 0;
			
			clock_get_uptime(&lastChangedTime);
			break;
		}
		
		prev = current;
		current = current->next;
	}
	
	if(current == NULL)
	{
		if(prev)
			prev->next = workRule;
		else
			this->root = workRule;

		//get rule id
		workRule->Retain();
		*rule = workRule;
		result = 0;
	}
	
//unlock:
	IOLockUnlock(lock);
	return result;
}

int 
Rules::DeleteRule(UInt32 ruleId)
{
	int result = -1;
	IOLockLock(lock);
	Rule* workRule = this->root;
	while (workRule)
	{
		if(workRule->id == ruleId)
		{
			workRule->state = RuleStateDeleted;
			RemoveFromChain(workRule);
			
			clock_get_uptime(&lastChangedTime);
			result = 0;
			break;
		}
		
		workRule = workRule->next;
	}
	
	IOLockUnlock(lock);
	return result;
}

int 
Rules::ActivateRule(UInt32 ruleId)
{
	int result = -1;
	
	IOLockLock(lock);
	Rule* workRule = this->root;
	while (workRule)
	{
		if(workRule->id == ruleId)
		{
			if(workRule->state == RuleStateInactive)
			{
				workRule->state = RuleStateActive;
				clock_get_uptime(&lastChangedTime);
				result = 0;
			}
			else
			{
				result = 1;
			}

			break;
		}
		
		workRule = workRule->next;
	}
	
	IOLockUnlock(lock);
	return result;
}

int 
Rules::DeactivateRule(UInt32 ruleId)
{
	int result = -1;

	IOLockLock(lock);
	Rule* workRule = this->root;
	while (workRule)
	{
		if(workRule->id == ruleId)
		{
			if(workRule->state == RuleStateInactive)
			{
				workRule->state = RuleStateActive;
				clock_get_uptime(&lastChangedTime);
				result = 0;
			}
			else
			{
				result = 1;//alredy inactive
			}
			break;
		}
		
		workRule = workRule->next;
	}

	IOLockUnlock(lock);
	return result;
}

//test


int
vn_rdwr_64FromKernelCode(
		   enum uio_rw rw,
		   struct vnode *vp,
		   uint64_t base,
		   int64_t len,
		   off_t offset,
		   enum uio_seg segflg,
		   int ioflg,
		   int *aresid,
		   proc_t p)
{
	uio_t auio;
	//int spacetype;
	vfs_context_t context;
	int error=0;
	//char uio_buf[ UIO_SIZEOF(1) ];
	
	//context.vc_thread = current_thread();
	//context.vc_ucred = cred;
	
//	if (UIO_SEG_IS_USER_SPACE(segflg)) {
//		spacetype = proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32;
//	}
//	else {
//		spacetype = UIO_SYSSPACE;
//	}
	auio = uio_create(1, offset, UIO_SYSSPACE, rw);
	uio_addiov(auio, base, len);
	
//#if CONFIG_MACF
//	/* XXXMAC
//	 * 	IO_NOAUTH should be re-examined.
// 	 *	Likely that mediation should be performed in caller.
//	 */
//	if ((ioflg & IO_NOAUTH) == 0) {
//		/* passed cred is fp->f_cred */
//		if (rw == UIO_READ)
//			error = mac_vnode_check_read(&context, cred, vp);
//		else
//			error = mac_vnode_check_write(&context, cred, vp);
//	}
//#endif
	

		if (rw == UIO_READ)
		{
			error = VNOP_READ(vp, auio, ioflg, context);
		}
		else 
		{
			error = VNOP_WRITE(vp, auio, ioflg, context);
		}
	
	if (aresid)
		// LP64todo - fix this
		*aresid = uio_resid(auio);
	else
		if (uio_resid(auio) && error == 0)
			error = EIO;
	return (error);
}

//end test
