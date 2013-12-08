#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/vnode_if.h>

#include "application.h"

void
hexdump(const unsigned char *sha1, char* buffer)
{
	static const char hexval[16] = { '0', '1', '2', '3','4', '5', '6', '7','8', '9', 'A', 'B','C', 'D', 'E', 'F' };
	int k = 0;
	for (int i = 0 ; i < SHA1_RESULTLEN; i++)
	{
		buffer[k++] = hexval[ ( (sha1[i] >> 4) & 0xF ) ];
		buffer[k++] = hexval[ ( sha1[i] & 0x0F ) ];
	}
	buffer[k] = 0;
}

char testText[] = "MMMMMMMMMMM";

void 
testOpenFile()
{
	static bool ex = true;
	
	if(ex)
	{
		vnode_t vp;
		vfs_context_t vfs = vfs_context_current();
		if (vnode_open("/file.txt", (O_CREAT | O_TRUNC | FWRITE), (0), 0, &vp, vfs) == 0)
		{
			
			uio_t auio;
			auio = uio_create(1, 0/*offset*/, UIO_SYSSPACE, UIO_WRITE);
			uio_addiov(auio, (user_addr_t)testText, sizeof(testText));
			
			VNOP_WRITE(vp, auio, /*ioflg*/ 0, vfs);
			
			::IOLog("file open \n");
			vnode_close(vp, 0, vfs);
		}
		else
		{
			::IOLog("file can't open \n");
		}

		ex = false;
	}
}

bool 
Applications::Init()
{
	closing = 0;
	
	if((lock = IOLockAlloc()))
	{
		if((lockRoutine = IOLockAlloc()))
		{
            
            if(KERN_SUCCESS == kernel_thread_start(CheckIsLiveRoutine, this, &thread))
//			if((thread = IOCreateThread(CheckIsLiveRoutine, this)))
			{
				if((processListener = kauth_listen_scope(KAUTH_SCOPE_FILEOP, CallbackProcessListener, this)))
				{
					return true;
				}
				
				OSIncrementAtomic(&closing);
			}
			
			IOLockFree(lockRoutine);
		}
		
		IOLockFree(lock);
	}
	
	return false;
}


void 
Applications::Free()
{
	OSIncrementAtomic(&closing);
	
	if(processListener)
		kauth_unlisten_scope(processListener);
	
	processListener = NULL;
	
	if(lock)
	{
		if(lockRoutine)
		{
			IOLockLock(lockRoutine);
			IOLockUnlock(lockRoutine);
			IOLockFree(lockRoutine);
			lockRoutine = NULL;
		}
		
		IOLockLock(lock);
		while (head)
			Remove(head)->Release();
		IOLockUnlock(lock);
		
		IOLockFree(lock);
		
		lock = NULL;
	}
}

Application* 
Applications::Get()
{
	if(closing)
		return NULL;
	
	//search in existing
	pid_t pid = proc_selfpid();
	IOLockLock(lock);	
	Application* result = head;
	
	while(result)
	{
		if(result->pid == pid)
		{
			result->Retain();
			IOLockUnlock(lock);
			return result;	
		}
		
		result = result->next;
	}
	
	result = Add(NULL, NULL, NULL);
	if(result)
		result->Retain();
	
	IOLockUnlock(lock);
	return result;	
}

void 
Applications::AddLocked(kauth_cred_t cred, vnode_t vnode, const char *filePath)
{
	IOLockLock(lock);
	Add(cred, vnode, filePath);
	IOLockUnlock(lock);
}

Application* 
Applications::Add(kauth_cred_t cred, vnode_t vnode, const char *filePath)
{
	if(closing)
		return NULL;
	
	char procName[MAXCOMLEN] = {0};

	Application *result = new Application();
	if(!result)
		return NULL;

	result->pid = proc_selfpid();
	result->p_pid = proc_selfppid();
	
	proc_selfname(procName, MAXCOMLEN);
	result->processName = OSString::withCString(procName);
	
	if(cred && vnode)
	{
		result->filePath = OSString::withCString(filePath);
		result->uid = kauth_cred_getuid(cred);
		result->gid = kauth_cred_getgid(cred);
		
		//read additional info from vnode
		vnode_attr va;
		VATTR_INIT(&va);
		VATTR_WANTED(&va, va_data_size);
		VATTR_WANTED(&va, va_modify_time);
		VATTR_WANTED(&va, va_create_time);

		if (vnode_getattr(vnode, &va, vfs_context_current()) && va.va_data_size != 0)
		{
			if(VATTR_IS_SUPPORTED(&va, va_data_size))
			{
				//TODO: check for changes
				result->dataSize = va.va_data_size;
			}
			
			if(VATTR_IS_SUPPORTED(&va, va_modify_time))
			{
				//TODO: check for changes
				result->modifyTime = va.va_modify_time;
			}

			if(VATTR_IS_SUPPORTED(&va, va_create_time))
			{
				//TODO: check for changes
				result->createTime = va.va_create_time;
			}
		} 
	}
	else
	{
		result->filePath = OSString::withCString("");
		result->uid = kauth_getuid();
		result->gid = kauth_getgid();
	}
	
	result->Retain();
	
	result->next = head;
	head = result;
	
	if(result->next)
		result->next->prev = result;
	
	countProcessesToCheck++;
	
	return result;
}

int 
Applications::CallbackProcessListener
(
 kauth_cred_t    credential,
 void *          idata,
 kauth_action_t  action,
 uintptr_t       arg0,
 uintptr_t       arg1,
 uintptr_t       arg2,
 uintptr_t       arg3
 )
{
	if(KAUTH_FILEOP_EXEC == action && idata != NULL)
		 ((Applications*) idata)->AddLocked(credential, (vnode_t)arg0, (const char *) arg1);
	
	return KAUTH_RESULT_DEFER;
}

void
Applications::CheckIsLiveRoutine(void *arg, wait_result_t waitResult)
{
	Applications *applications = (Applications*) arg;
	Application *checked = NULL;
	
	IOLockLock(applications->lockRoutine);
	
	while(applications->closing == 0)
	{
		if(applications->countProcessesToCheck == 0)
			IOSleep(500);
		
		if(applications->closing)
			break;
	
		IOLockLock(applications->lock);
		if(checked == NULL)
			checked = applications->head;
		else
		{
			Application* a = checked;
			checked = checked->next;
			a->Release();
		}
		
		if(applications->countProcessesToCheck > 0)
			applications->countProcessesToCheck--;
		
		if(checked)
		{	
			proc_t pr = proc_find(checked->pid);
			if(pr)
			{
				proc_rele(pr);
				checked->Retain();//cashing for next loop
			}
			else
			{
				applications->Remove(checked);
				checked->Release();
				checked = NULL;
				applications->countProcessesToCheck++;
			}
		}
		IOLockUnlock(applications->lock);
	}	

	IOLockUnlock(applications->lockRoutine);
    thread_t currentThread = applications->thread;
	applications->thread = NULL;
	//IOExitThread();
    thread_deallocate(currentThread);
    thread_terminate(currentThread);
}

