#include "client.h"

//#ifdef KERNEL_PRIVATE

/*
 * internal structure maintained for each register controller
 */
//struct ctl_cb;
//struct socket;

//struct kctl
//{
//	TAILQ_ENTRY(kctl)		next;					/* controller chain */
//	
//	/* controller information provided when registering */
//	char					name[MAX_KCTL_NAME];	/* unique nke identifier, provided by DTS */
//	u_int32_t				id;
//	u_int32_t				reg_unit;
//	
//	/* misc communication information */
//	u_int32_t				flags;					/* support flags */
//	u_int32_t				recvbufsize;			/* request more than the default buffer size */
//	u_int32_t				sendbufsize;			/* request more than the default buffer size */
//	
//	/* Dispatch functions */
//	ctl_connect_func		connect;				/* Make contact */
//	ctl_disconnect_func		disconnect;				/* Break contact */
//	ctl_send_func			send;					/* Send data to nke */
//	ctl_setopt_func			setopt;					/* set kctl configuration */
//	ctl_getopt_func			getopt;					/* get kctl configuration */
//	
//	TAILQ_HEAD(, ctl_cb)	kcb_head;
//	u_int32_t				lastunit;
//};
//
//struct ctl_cb {
//	TAILQ_ENTRY(ctl_cb)		next;					/* controller chain */
//	lck_mtx_t				*mtx;
//	/*struct*/ socket_t			so;					/* controlling socket */
//	struct kctl				*kctl;					/* back pointer to controller */
//	u_int32_t				unit;
//	void					*userdata;
//};

//#endif /* KERNEL_PRIVATE */

void 
Client::ClearQueue(ClientMessageNode *root)
{
	while(root)
	{
		ClientMessageNode *curr = root;
		root = root->next;
		curr->message->Release();
		delete(curr);
	}
}

bool 
Client::InitWithClient(kern_ctl_ref kernelKontrolReference, UInt32 unit)
{
	//IOLog("client state refernces: %ld; thread: %p; lQueue: %p; lThread: %p; nest: %p \n", this->references, this->thread, this->lockQueue, this->lockWorkThread, this->next);
	
    //kernel_thread_start
    
	this->registredMessageClases = MessageClassFirewall | MessageClassCommon;
	
	if((this->lockQueue = IOSimpleLockAlloc()))
	{
		if((this->lockWorkThread = IOLockAlloc()))
		{
			this->kernelKontrolReference = kernelKontrolReference;
			this->unit = unit;
			
            if(KERN_SUCCESS == kernel_thread_start(Client::SendThread, this, &this->thread))
            {
                this->references = 1;
                return true;
            }
            
//			if((this->thread = IOCreateThread(Client::SendThread, this)))
//			{
//				//IOLog("client created \n");
//				this->references = 1;
//				return true;
//			}
			
			IOLockFree(this->lockWorkThread);
			//IOLog("client can't create thread \n");//TODO: refactor
		}
		
		IOSimpleLockFree(this->lockQueue);
		//IOLog("client can't create lock thread \n");//TODO: refactor
	}
	
	//IOLog("client can't create lock client \n");//TODO: refactor
	return false;
}

void 
Client::CloseSignal()
{
	//IOLog("cliend send close signal\n");
	OSIncrementAtomic(&this->exitState);
	IOLockWakeup(this->lockWorkThread, 0, false);
}

void
Client::Free()
{
	//u_int32_t ui = this->unit;
 	//IOLog("client begin destroed %u\n", ui);
	
	if(this->lockQueue)
	{
		ClientMessageNode * node = NULL;

		IOInterruptState istate = IOSimpleLockLockDisableInterrupt(this->lockQueue);
		
		node = this->messageQueueHead;
		this->messageQueueHead = NULL;
		this->messageQueueLast = NULL;
		
		IOSimpleLockUnlockEnableInterrupt(this->lockQueue, istate);
		
		ClearQueue(node);
		
		IOSimpleLockFree(this->lockQueue);
		this->lockQueue = NULL;
	}
	
	if(this->lockWorkThread)
	{
		IOLockFree(this->lockWorkThread);
		this->lockWorkThread = NULL;
	}
	
	SimpleBase::Free();
	//::IOLog("client destored %u\n", ui);
}

void 
Client::Send(Message* message)
{
	if(message == NULL || this->exitState)
		return;
	
	if(!(message->raw.type & this->registredMessageClases))
		return;
	
	ClientMessageNode * node = new ClientMessageNode();
	if(!node)
		return;

	message->Retain();
	node->message = message;
	node->next = NULL;
	
	IOInterruptState istate = IOSimpleLockLockDisableInterrupt(this->lockQueue);
	
	if(this->messageQueueLast == NULL)
		this->messageQueueHead = node;
	else
		this->messageQueueLast->next = node;
	
	this->messageQueueLast = node;

	IOSimpleLockUnlockEnableInterrupt(this->lockQueue, istate);
	IOLockWakeup(this->lockWorkThread, 0, false);
}

void 
Client::SendThread(void* arg, wait_result_t waitResult)
{
	Client* client = (Client*)arg;
	client->Retain();
	ClientMessageNode *node = NULL;
	UInt64 lastSendTime = 0;
	UInt64 currentTime;
	UInt64 diff;
	size_t size;
	int k;

	IOLockLock(client->lockWorkThread);

	while(1)
	{
		IOLockSleep(client->lockWorkThread, 0, THREAD_UNINT);
		
		if(client->exitState)
			goto exit;
		
		//sllep if nedded
		clock_get_uptime(&currentTime);
		absolutetime_to_nanoseconds( currentTime - lastSendTime, &diff);
		
		if(diff < 500000000)//nano seconds
			IOSleep((500000000 - diff)/1000000);
		
		if(client->exitState)
			goto exitAndClearQueue;
		
		IOInterruptState istate = IOSimpleLockLockDisableInterrupt(client->lockQueue);

		node = client->messageQueueHead;
		client->messageQueueHead = NULL;
		client->messageQueueLast = NULL;
		
		IOSimpleLockUnlockEnableInterrupt(client->lockQueue, istate);
		
		while(node)
		{
			size = 0;
			k = 0;
			do
			{
				if(client->exitState)
					goto exitAndClearQueue;

				ctl_getenqueuespace(client->kernelKontrolReference, client->unit, &size);
				if(size < node->message->raw.size)
				{
					if(k++ < 3)
					{
						IOSleep(200);
						continue;
					}
					else
						::IOLog("client is bisy. can't recivie data.\n");
				}
				else
				{
					if(client->exitState)
						goto exitAndClearQueue;
					
					switch(ctl_enqueuedata(client->kernelKontrolReference, client->unit, &node->message->raw, node->message->raw.size, 0))
					{
						case EINVAL: // - Invalid parameters.
							::IOLog("ctl_enqueuedata return: Invalid parameter.\n");
							break;
						case EMSGSIZE: // - The buffer is too large.
							::IOLog("ctl_enqueuedata return: The buffer is too large.\n");
							break;
						case ENOBUFS: // - The queue is full or there are no free mbufs.
							::IOLog("ctl_enqueuedata return: The queue is full or there are no free mbufs.\n");
							break;
					}
				}				
			}while(false);

			
			if(client->exitState)
				goto exitAndClearQueue;

			ClientMessageNode *deletedNode = node;
			node = node->next;
			deletedNode->message->Release();
			delete(deletedNode);
		}
		
		clock_get_uptime(&lastSendTime);
	}
	
exitAndClearQueue:
	ClearQueue(node);
exit:
	IOLockUnlock(client->lockWorkThread);
	//IOLog("exit send thread unit: %lu\n", client->unit);
    thread_t currentThead = client->thread;
	client->Release();
    thread_deallocate(currentThead);
    thread_terminate(currentThead);
    //current_thread()
    
	//IOExitThread();
}

bool 
Client::RegisterMessageClasses(UInt16 classes)
{
	return (OSBitOrAtomic(classes, &this->registredMessageClases) & classes) == classes;
}

bool 
Client::UnregisterMessageClasses(UInt16 classes)
{
	return (OSBitOrAtomic(~classes, &this->registredMessageClases) & classes) == 0;
}	

/*
void
Client::ShowSocketStates()
{
	if(this->kernelKontrolReference)
	{
		struct ctl_cb	*kcb_next = NULL;
		struct kctl		*kc = (struct kctl*)this->kernelKontrolReference;
		
		//kc->kcb_head.tqh_first-
		TAILQ_FOREACH(kcb_next, &kc->kcb_head, next) 
		{
			IOLog("from class: %lu  from kctl-id: %u unit: %u is same: %d \n", this->unit, kc->id, kcb_next->unit, kcb_next->userdata == this);

			int isConnected = sock_isconnected(kcb_next->so);
			
			IOLog("client: %lu  state is: %d \n", this->unit, isConnected);
			
			if(isConnected)
			{
				isConnected = sock_shutdown(kcb_next->so, SHUT_RDWR);
				IOLog("sock_shutdown return: %d \n", isConnected);
				
				if(!isConnected)
					sock_close(kcb_next->so);
				
				//IOLog("invoke disconnect \n");
				//kc->disconnect(kc, kcb_next->unit, kcb_next->userdata);
			}
		}
		
		//kc->kcb_head.tqh_first;
		
//		while(kcb_next = TAILQ_FIRST(&kc->kcb_head))
//		{
//			//kcb_next->kctl = 0;
//			//kcb_next->unit = 0;
//			TAILQ_REMOVE(&kc->kcb_head, kcb_next, next);
//		}
		
		
		//kc->disconnect(kc, kc->reg_unit, this);
	}
}
 */



