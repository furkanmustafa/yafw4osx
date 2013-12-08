#ifndef WATCH_MESSAGES_TYPE_H
#define WATCH_MESSAGES_TYPE_H

#include <libkern/OSTypes.h>
//#include <IOKit/IOLib.h>
#include <string.h>

enum MessagesClass
{
	MessageClassInfoRules							= 0x0100,
	MessageClassInfoSockets							= 0x0200,
	MessageClassProviderOfRules						= 0x0400,
	MessageClassFirewall							= 0x0800,
	MessageClassClient								= 0x1000,
	MessageClassCommon								= 0x2000
};

enum ServerMessagesType 
{
	MessageTypeText									= MessageClassCommon | 0x01, //dummy
	
	MessageTypeSfltUnregistered						= MessageClassCommon | 0x02, //debug
	MessageTypeSfltAttach							= MessageClassCommon | 0x03, //debug
	MessageTypeSfltDetach							= MessageClassCommon | 0x04, //debug
	MessageTypeSfltNotify							= MessageClassCommon | 0x05, //debug
	MessageTypeSfltGetPeerName						= MessageClassCommon | 0x06, //debug
	MessageTypeSfltGetSockName						= MessageClassCommon | 0x07, //debug
	MessageTypeSfltDataIn							= MessageClassCommon | 0x08, //debug
	MessageTypeSfltDataOut							= MessageClassCommon | 0x09, //debug
	MessageTypeSfltConnectIn						= MessageClassCommon | 0x0A, //debug
	MessageTypeSfltConnectOut						= MessageClassCommon | 0x0B, //debug
	MessageTypeSfltBind								= MessageClassCommon | 0x0C, //debug
	MessageTypeSfltSetOption						= MessageClassCommon | 0x0D, //debug
	MessageTypeSfltGetOption						= MessageClassCommon | 0x0E, //debug
	MessageTypeSfltListen							= MessageClassCommon | 0x0F, //debug
	MessageTypeSfltIoctl							= MessageClassCommon | 0x10, //debug
	MessageTypeSfltAccept							= MessageClassCommon | 0x11, //debug
	
	MessageTypeRequestRule							= MessageClassProviderOfRules |  0x01,
	
	MessageTypeRuleAdded							= MessageClassInfoRules | 0x01,
	MessageTypeRuleDeleted							= MessageClassInfoRules | 0x02,
	MessageTypeRuleDeactivated						= MessageClassInfoRules | 0x03,
	MessageTypeRuleActivated						= MessageClassInfoRules | 0x04,
	
	MessageTypeSocketData							= MessageClassInfoSockets | 0x07,
	MessageTypeSocketOpen							= MessageClassInfoSockets | 0x08,
	MessageTypeSocketClosed							= MessageClassInfoSockets | 0x09,
	
	MessageTypeFirewallActivated					= MessageClassFirewall | 0x01,
	MessageTypeFirewallDeactivated					= MessageClassFirewall | 0x02,

	MessageTypeClientSubscribedAsaProviderOfRules	= MessageClassFirewall | 0x03,
	MessageTypeClientUnsubscribedAsaProviderOfRules	= MessageClassFirewall | 0x04,
	MessageTypeClientSubscribedToInfoRules			= MessageClassFirewall | 0x05,
	MessageTypeClientUnsubscribedFromInfoRules		= MessageClassFirewall | 0x06,
	MessageTypeClientSubscribedToInfoSockets		= MessageClassFirewall | 0x07,
	MessageTypeClientUnsubscribedFromInfoSockets	= MessageClassFirewall | 0x08,

	MessageTypeFirewallClosing						= MessageClassFirewall | 0x09
};

enum ClientMessagesType
{
	MessageTypeAddRule								= MessageClassClient | 0x01,
	MessageTypeDeleteRule							= MessageClassClient | 0x02,
	MessageTypeActivateRule							= MessageClassClient | 0x03,
	MessageTypeDeactivateRule						= MessageClassClient | 0x04,

	MessageTypeActivateFirewall						= MessageClassClient | 0x05,
	MessageTypeDeactivateFirewall					= MessageClassClient | 0x06,

	MessageTypeSubscribeAsaProviderOfRules			= MessageClassClient | 0x07,
	MessageTypeUnsubscribeAsaProviderOfRules		= MessageClassClient | 0x08,
	MessageTypeSubscribeToInfoRules					= MessageClassClient | 0x09,
	MessageTypeUnsubscribeFromInfoRules				= MessageClassClient | 0x0A,
	MessageTypeSubscribeToInfoSockets				= MessageClassClient | 0x0B,
	MessageTypeUnsubscribeFromInfoSockets			= MessageClassClient | 0x0C
};

struct TimeSpec
{
	SInt32 sec;
	SInt32 nsec;
};

struct SockAddress
{
	UInt8 len;
	UInt8 family;

	static size_t Copy(const SockAddress *from, void* to)
	{
		if(!from)
		{
			SockAddress* toAsSockAddress = (SockAddress*)to;
			toAsSockAddress->family =  0/*AF_UNSPEC*/;
			toAsSockAddress->len = sizeof(SockAddress);

			return toAsSockAddress->len;
		}

		memcpy(to, from, from->len);
		return from->len;
	}
};

struct SockAddressIP4 : SockAddress
{
	UInt16	port;//or mask or 0 for all
	UInt32	addr;
};

struct SockAddressIP4WithMask : SockAddressIP4
{
	UInt8	addrMask;
};

struct SockAddressIP6 : SockAddress
{
	UInt16	port;
	UInt32	flowInfo;
	UInt8   addr[16];//TODO: replace with struct in6_addr	sin6_addr;	/* IP6 address */
	UInt32	scopeId;
};

struct SockAddressIP6WithMask : SockAddressIP6
{
	UInt8 addrMask;//??? mask
};

struct SockAddressUnix : SockAddress
{
	char 	path[104];
};

struct SockAddressUnixWithMask : SockAddressUnix
{
	char 	pathMask[104];
};

struct RawRule
{
	UInt16 size;
	UInt16 type;//inbound traffic, outbound traffic
};

struct RawIP4Rule : RawRule
{
	SockAddressIP4WithMask from;
	SockAddressIP4WithMask to;
};

struct rawIP6Rule : RawRule
{
	SockAddressIP6WithMask from;
	SockAddressIP6WithMask to;
};

struct RawUnixRule : RawRule
{
	SockAddressUnixWithMask from;
	SockAddressUnixWithMask to;
};

struct RawMessageBase 
{
	UInt16 size;
	UInt16 type;
	
	inline void Init(UInt16 size, UInt16 type){this->size = size, this->type = type;}
	
};

struct RawMessageSfltUnregistered : public RawMessageBase
{
	//	static void		Unregistered(sflt_handle handle);
	inline void Init()
	{
		RawMessageBase::Init(sizeof(RawMessageSfltUnregistered), MessageTypeSfltUnregistered);
	}
};

struct RawMessageSfltAttach : public RawMessageBase		
{
	//	static errno_t	Attach(void	**cookie, socket_t so);
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	UInt16 proto;
	
	inline void Init(UInt32 pid, UInt32 uid, UInt64 so, UInt16 proto)
	{
		RawMessageBase::Init(sizeof(RawMessageSfltAttach), MessageTypeSfltAttach);

		this->pid = pid;
		this->uid = uid;
		this->so = so;
		this->proto = proto;
	}
};

struct RawMessageSfltDetach : public RawMessageBase		
{
	//	static void		Detach(void	*cookie, socket_t so);
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	
	inline void Init(UInt32 pid, UInt32 uid,UInt64 so)
	{
		RawMessageBase::Init(sizeof(RawMessageSfltDetach), MessageTypeSfltDetach);

		this->pid = pid;
		this->uid = uid;
		this->so = so;
	}
};

struct RawMessageSfltNotify : public RawMessageBase		
{
	//	static void		Notify(void *cookie, socket_t so, sflt_event_t event, void *param);
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	UInt16 event;
	
	inline void Init(UInt32 pid, UInt32 uid, UInt64 so, UInt16 event)
	{
		RawMessageBase::Init(sizeof(RawMessageSfltNotify), MessageTypeSfltNotify);

		this->pid = pid;
		this->uid = uid;
		this->so = so;
		this->event = event;
	}
};

struct RawMessageSfltGetPeerName : public RawMessageBase	
{
	//	static int		GetPeerName(void *cookie, socket_t so, sockaddr **sa);
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	SockAddress sa;
	
	inline void Init(UInt16 size, UInt32 pid, UInt32 uid, UInt64 so , SockAddress *sa)
	{
		RawMessageBase::Init(size, MessageTypeSfltGetPeerName);

		this->pid = pid;
		this->uid = uid;
		this->so = so;

		SockAddress::Copy(sa, &this->sa);
	}
	
	inline static UInt16 GetNeededSize(SockAddress *sa)
	{
		return sizeof(RawMessageSfltGetPeerName) + (sa ? sa->len - sizeof(SockAddress) : 0); 
	}
};

struct RawMessageSfltGetSockName : public RawMessageBase	
{
	//	static int		GetSockName(void *cookie, socket_t so, sockaddr **sa);
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	SockAddress sa;
	
	inline void Init(UInt16 size, UInt32 pid, UInt32 uid, UInt64 so , SockAddress *sa)
	{
		RawMessageBase::Init(size, MessageTypeSfltGetSockName);

 		this->pid = pid;
		this->uid = uid;
		this->so = so;

		SockAddress::Copy(sa, &this->sa);
	}

	inline static UInt16 GetNeededSize(SockAddress *sa)
	{
		return sizeof(RawMessageSfltGetSockName) + (sa ? sa->len - sizeof(SockAddress) : 0); 
	}
};

struct RawMessageSfltDataIn : public RawMessageBase		
{
	//	static errno_t	DataIn(void *cookie, socket_t so, const sockaddr *from, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags);
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	UInt16 proto;
	SockAddress from;
	
	inline void Init(UInt16 size, UInt32 pid, UInt32 uid, UInt64 so, UInt16 proto, SockAddress *from)
	{
		RawMessageBase::Init(size, MessageTypeSfltDataIn);
		
		this->pid = pid;
		this->uid = uid;
		this->so = so;
		this->proto = proto;

		SockAddress::Copy(from, &this->from);
	}
	
	inline static UInt16 GetNeededSize(SockAddress *sa)
	{
		return sizeof(RawMessageSfltDataIn) + (sa ? sa->len - sizeof(SockAddress) : 0); 
	}
};

struct RawMessageSfltDataOut : public RawMessageBase		
{
	//	static errno_t	DataOut(void *cookie, socket_t so, const sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags);
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	UInt16 proto;
	SockAddress to;
	
	inline void Init(UInt16 size, UInt32 pid, UInt32 uid, UInt64 so, UInt16 proto, SockAddress *to)
	{
		RawMessageBase::Init(size, MessageTypeSfltDataOut);
		
		this->pid = pid;
		this->uid = uid;
		this->so = so;
		this->proto = proto;

		SockAddress::Copy(to, &this->to);
	}

	inline static UInt16 GetNeededSize(SockAddress *sa)
	{
		return sizeof(RawMessageSfltDataOut) + (sa ? sa->len - sizeof(SockAddress) : 0); 
	}
};

struct RawMessageSfltConnectIn : public RawMessageBase	
{
	//	static errno_t	ConnectIn(void *cookie, socket_t so, const sockaddr *from);
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	SockAddress from;
	
	inline void Init(UInt16 size, UInt32 pid, UInt32 uid, UInt64 so, SockAddress *from)
	{
		RawMessageBase::Init(size, MessageTypeSfltConnectIn);
		
		this->pid = pid;
		this->uid = uid;
		this->so = so;

		SockAddress::Copy(from, &this->from);
	}

	inline static UInt16 GetNeededSize(SockAddress *from)
	{
		return sizeof(RawMessageSfltConnectIn) + (from ? from->len - sizeof(SockAddress) : 0); 
	}
};

struct RawMessageSfltConnectOut : public RawMessageBase	
{
	//	static errno_t	ConnectOut(void *cookie, socket_t so, const sockaddr *to);
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	SockAddress to;
	
	inline void Init(UInt16 size, UInt32 pid, UInt32 uid, UInt64 so, SockAddress *to)
	{
		RawMessageBase::Init(size, MessageTypeSfltConnectOut);
		
		this->pid = pid;
		this->uid = uid;
		this->so = so;

		SockAddress::Copy(to, &this->to);
	}

	inline static UInt16 GetNeededSize(SockAddress *to)
	{
		return sizeof(RawMessageSfltConnectOut) + (to ? to->len - sizeof(SockAddress) : 0); 
	}
};

struct RawMessageSfltBind : public RawMessageBase			
{
	//	static errno_t	Bind(void *cookie, socket_t so, const sockaddr *to);
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	SockAddress to;
	
	inline void Init(UInt16 size, UInt32 pid, UInt32 uid, UInt64 so, SockAddress *to)
	{
		RawMessageBase::Init(size, MessageTypeSfltBind);
		
		this->pid = pid;
		this->uid = uid;
		this->so = so;

		SockAddress::Copy(to, &this->to);
	}

	inline static UInt16 GetNeededSize(SockAddress *sa)
	{
		return sizeof(RawMessageSfltBind) + (sa ? sa->len - sizeof(SockAddress) : 0); 
	}
};

struct RawMessageSfltSetOption : public RawMessageBase	
{
	//	static errno_t	SetOption(void *cookie, socket_t so, sockopt_t opt);
	
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	UInt32 optionName;
	inline void Init(UInt32 pid, UInt32 uid, UInt64 so, UInt32 optionName)
	{
		RawMessageBase::Init(sizeof(RawMessageSfltSetOption), MessageTypeSfltSetOption);
		
		this->pid = pid;
		this->uid = uid;
		this->so = so;
		this->optionName = optionName;
	}
};

struct RawMessageSfltGetOption : public RawMessageBase	
{
	//	static errno_t	GetOption(void *cookie, socket_t so, sockopt_t opt);
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	UInt32 optionName;
	
	inline void Init(UInt32 pid, UInt32 uid, UInt64 so, UInt32 optionName)
	{
		RawMessageBase::Init(sizeof(RawMessageSfltGetOption), MessageTypeSfltGetOption);
		
		this->pid = pid;
		this->uid = uid;
		this->so = so;
		this->optionName = optionName;
	}
};

struct RawMessageSfltListen : public RawMessageBase		
{
	//	static errno_t	Listen(void *cookie, socket_t so);
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	
	inline void Init(UInt32 pid, UInt32 uid, UInt64 so)
	{
		RawMessageBase::Init(sizeof(RawMessageSfltListen), MessageTypeSfltListen);
		
		this->pid = pid;
		this->uid = uid;
		this->so = so;
	}
};

struct RawMessageSfltIoctl : public RawMessageBase		
{
	//	static errno_t	Ioctl(void *cookie, socket_t so, u_int32_t request, const char* argp);
	UInt32 pid;
	UInt32 uid;
	UInt64 so;
	UInt32 request;
	
	inline void Init(UInt32 pid, UInt32 uid, UInt64 so, UInt32 request)
	{
		RawMessageBase::Init(sizeof(RawMessageSfltIoctl), MessageTypeSfltIoctl);
		
		this->pid = pid;
		this->uid = uid;
		this->so = so;
		this->request = request;
	}
};

struct RawMessageSfltAccept : public RawMessageBase		
{
	//	static errno_t	Accept(void *cookie, socket_t so_listen, socket_t so, const sockaddr *local, const sockaddr *remote);
	UInt32 pid;
	UInt32 uid;
	UInt64 soListen;
	UInt64 so;
	
	UInt8 data[4];//local , remote
	
	inline void Init(UInt16 size, UInt32 pid, UInt32 uid, UInt64 soListen, UInt64 so, const SockAddress *local, const SockAddress *remote)
	{
		RawMessageBase::Init(size, MessageTypeSfltAccept);
		
		this->pid = pid;
		this->uid = uid;
		this->soListen = soListen;
		this->so = so;
		
		size_t offset = SockAddress::Copy(local, data);
		SockAddress::Copy(remote, data + offset);
	}
	
	inline SockAddress* GetLocal()
	{
		return (SockAddress*)data;
	}
	
	inline SockAddress* GetRemote()
	{
		return (SockAddress*)(data + GetLocal()->len);
	}
	
	inline static UInt16 GetNeededSize(SockAddress *local, SockAddress *remote)
	{
		return sizeof(RawMessageSfltAccept) + (local ? local->len : sizeof(SockAddress)) + (remote ? remote->len : sizeof(SockAddress)) - 4; 
	}
};

struct RawMessageText : public RawMessageBase
{
	char textBuffer[4];
};

struct RawMessageRequestRule : public RawMessageBase
{
	UInt16 processNameOffset;//0 for all
	UInt16 filePathOffset;//0 for all
	
	UInt16 sockDomain;//0 for all
	UInt16 sockType;//0 for all
	UInt16 sockProtocol;// 0 fro all	
	UInt16 fromSockAddressOffset;// 0 for all
	UInt16 toSockAddressOffset;
	
	UInt8 direction;//0 both. 1 incoming, 2 outgoung
	
	UInt32 pid;
	UInt32 uid;
	
	char buffer[4];
	
	//TODO: implement
};

struct RawMessageFirewallClosing : public RawMessageBase
{
	inline void Init(){ RawMessageBase::Init(sizeof(RawMessageFirewallClosing), MessageTypeFirewallClosing);};
};

/////
struct RawMessageSocketData : public RawMessageBase
{
	UInt8		stateOperation;
	//UInt8		fromAddressSize;
	//UInt8		toAddressSize;
	//UInt8		processNameSize;
	UInt8		direction;
	UInt32		stateByRuleId;
	UInt32		pid;//pid_t
	UInt32		uid;//uid_t
	UInt64		so;//socket_t
	UInt32		packets;
	UInt32		bytes;
	char		data[3];//from address, to address ?? process name

	inline void Init(UInt16 size, UInt8 direction, UInt8 stateOperation, UInt32 stateByRuleId, UInt32 pid, UInt32 uid,UInt64 so, UInt32 packets, UInt32 bytes, const SockAddress *from, const SockAddress *to, const char *processName, int processNameSize)
	{
		int currentOffset = 0;

		RawMessageBase::Init(size, MessageTypeSocketData);

		this->stateOperation = stateOperation;
		this->stateByRuleId = stateByRuleId;
		this->pid = pid;
		this->uid = uid;
		this->so = (UInt64)so;
		this->packets = packets;
		this->bytes = bytes;
		this->direction = direction;

		currentOffset += SockAddress::Copy(from, this->data + currentOffset);
		currentOffset += SockAddress::Copy(to, this->data + currentOffset);

//		if(processNameSize != 0)
//		{
//			this->processNameSize = processNameSize;
//			memcpy(this->data + currentOffset, processName, this->processNameSize);
//			currentOffset += this->processNameSize;
//		}
//		else
//		{
//			this->processNameSize = 0;
//			*(this->data + currentOffset) = 0;
//		}
	}

	inline SockAddress* GetFromSocketAddress()
	{
		return (SockAddress*)this->data;
	}

	inline SockAddress* GetToSocketAddress()
	{
		return (SockAddress*)(this->data + GetFromSocketAddress()->len);
	}

	inline char* GetProcessName()
	{
		return 0;
	}

};

struct RawMessageSocketOpen : public RawMessageBase
{
	UInt64 so;

	inline void Init(UInt64 so)
	{
		RawMessageBase::Init(sizeof(RawMessageSocketOpen), MessageTypeSocketOpen);
		this->so = so;
	}
};

struct RawMessageSocketClosed : public RawMessageBase
{
	UInt64 so;

	inline void Init(UInt64 so)
	{
		RawMessageBase::Init(sizeof(RawMessageSocketClosed), MessageTypeSocketClosed);
		this->so = so;
	}
};


#pragma mark client action response

struct RawMessageClientActionResponse : public RawMessageBase
{
	UInt32 unitId;
	UInt32 clientMessageId;
	UInt32 actionState;

	inline void Init(UInt16 size, UInt16 type, UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
	{
		RawMessageBase::Init(size, type);
		this->unitId = unitId;
		this->clientMessageId = clientMessageId;
		this->actionState = actionState;
	}
};

struct RawMessageRuleAdded : public RawMessageClientActionResponse
{
	UInt32 ruleId;//rule
	
	inline void Init(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState , UInt32 ruleId)
	{ 
		RawMessageClientActionResponse::Init(sizeof(RawMessageRuleAdded), MessageTypeRuleAdded, unitId, clientMessageId, actionState);
		this->ruleId = ruleId;
	}
};

struct RawMessageRuleDeleted : public RawMessageClientActionResponse
{
	UInt32 ruleId;//rule

	inline void Init(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState , UInt32 ruleId)
	{ 
		RawMessageClientActionResponse::Init(sizeof(RawMessageRuleDeleted), MessageTypeRuleDeleted, unitId, clientMessageId, actionState);
		this->ruleId = ruleId;
	}
};

struct RawMessageRuleDeactivated : public RawMessageClientActionResponse
{
	UInt32 ruleId;//rule
	
	inline void Init(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState , UInt32 ruleId)
	{ 
		RawMessageClientActionResponse::Init(sizeof(RawMessageRuleDeactivated), MessageTypeRuleDeactivated, unitId, clientMessageId, actionState);
		this->ruleId = ruleId;
	}
};

struct RawMessageRuleActivated : public RawMessageClientActionResponse
{
	UInt32 ruleId;//rule

	inline void Init(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState , UInt32 ruleId)
	{ 
		RawMessageClientActionResponse::Init(sizeof(RawMessageRuleActivated), MessageTypeRuleActivated, unitId, clientMessageId, actionState);
		this->ruleId = ruleId;
	}
};

struct RawMessageClientSubscribedAsaProviderOfRules : public RawMessageClientActionResponse
{
	inline void Init(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
	{ 
		RawMessageClientActionResponse::Init(sizeof(RawMessageClientSubscribedAsaProviderOfRules), MessageTypeClientSubscribedAsaProviderOfRules, unitId, clientMessageId, actionState);
	}
};

struct RawMessageClientUnsubscribedAsaProviderOfRules : public RawMessageClientActionResponse
{
	inline void Init(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
	{ 
		RawMessageClientActionResponse::Init(sizeof(RawMessageClientUnsubscribedAsaProviderOfRules), MessageTypeClientUnsubscribedAsaProviderOfRules, unitId, clientMessageId, actionState);
	}	
};

struct RawMessageClientSubscribedToInfoRules : public RawMessageClientActionResponse
{
	inline void Init(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
	{ 
		RawMessageClientActionResponse::Init(sizeof(RawMessageClientSubscribedToInfoRules), MessageTypeClientSubscribedToInfoRules, unitId, clientMessageId, actionState);
	}	
};

struct RawMessageClientUnsubscribedFromInfoRules : public RawMessageClientActionResponse
{
	inline void Init(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
	{ 
		RawMessageClientActionResponse::Init(sizeof(RawMessageClientUnsubscribedFromInfoRules), MessageTypeClientUnsubscribedFromInfoRules, unitId, clientMessageId, actionState);
	}	
};


struct RawMessageClientSubscribedToInfoSockets : public RawMessageClientActionResponse
{
	inline void Init(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
	{ 
		RawMessageClientActionResponse::Init(sizeof(RawMessageClientSubscribedToInfoSockets), MessageTypeClientSubscribedToInfoSockets, unitId, clientMessageId, actionState);
	}	
};

struct RawMessageClientUnsubscribedFromInfoSockets : public RawMessageClientActionResponse
{
	inline void Init(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
	{ 
		RawMessageClientActionResponse::Init(sizeof(RawMessageClientUnsubscribedFromInfoSockets), MessageTypeClientUnsubscribedFromInfoSockets, unitId, clientMessageId, actionState);
	}	
};

struct RawMessageFirewallActivated : public RawMessageClientActionResponse
{
	inline void Init(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
	{ 
		RawMessageClientActionResponse::Init(sizeof(RawMessageFirewallActivated), MessageTypeFirewallActivated, unitId, clientMessageId, actionState);
	}	
};

struct RawMessageFirewallDeactivated : public RawMessageClientActionResponse
{
	inline void Init(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
	{ 
		RawMessageClientActionResponse::Init(sizeof(RawMessageFirewallDeactivated), MessageTypeFirewallDeactivated, unitId, clientMessageId, actionState);
	}	
};


#pragma mark Client messages

struct RawMessageClientAction : public RawMessageBase
{
	UInt32 messageId;

	inline void Init(UInt16 size, UInt16 type, UInt32 messageId)
	{
		RawMessageBase::Init(size, type);
		this->messageId = messageId;
	}
};

struct RawMessageAddRule : public RawMessageClientAction 
{
	UInt32 id;
	UInt16 processNameOffset;//0 for all
	UInt16 filePathOffset;//0 for all
	
	UInt16 sockDomain;//0 for all
	UInt16 sockType;//0 for all
	UInt16 sockProtocol;// 0 fro all	
	UInt16 fromSockAddressOffset;// 0 for all
	UInt16 toSockAddressOffset;
	
	UInt8 direction;//0 both. 1 incoming, 2 outgoung
	UInt8 allow;//0 denny, 1 allow
	UInt8 state;
	char buffer[1];
	
	char *GetProcessName(){ return (char*)this + processNameOffset; }
	char *GetFilePath(){ return (char*)this + filePathOffset;}
	SockAddress *GetFromSockAddress(){ return (SockAddress*) ((fromSockAddressOffset) ? (char*)this + fromSockAddressOffset : 0);}
	SockAddress *GetToSockAddress(){ return (SockAddress*) ((toSockAddressOffset) ? (char*)this + toSockAddressOffset : 0);}
	
	//TODO: by parent struct initialization
};

struct RawMessageDeleteRule : public RawMessageClientAction 
{
	UInt32 ruleId;
	
	inline void Init(UInt32 messageId, UInt32 ruleId)
	{
		RawMessageClientAction::Init(sizeof(RawMessageDeleteRule), MessageTypeDeleteRule, messageId);
		this->ruleId = ruleId;
	}
};

struct RawMessageActivateRule : public RawMessageClientAction 
{
	UInt32 ruleId;
	
	inline void Init(UInt32 messageId, UInt32 ruleId)
	{
		RawMessageClientAction::Init(sizeof(RawMessageActivateRule), MessageTypeActivateRule, messageId);
		this->ruleId = ruleId;
	}
};

struct RawMessageDeactivateRule : public RawMessageClientAction 
{
	UInt32 ruleId;
	
	inline void Init(UInt32 messageId, UInt32 ruleId)
	{
		RawMessageClientAction::Init(sizeof(RawMessageDeactivateRule), MessageTypeDeactivateRule, messageId);
		this->ruleId = ruleId;
	}
};

struct RawMessageActivateFirewall : public RawMessageClientAction 
{
	inline void Init(UInt32 messageId)
	{
		RawMessageClientAction::Init(sizeof(RawMessageActivateFirewall), MessageTypeActivateFirewall, messageId);
	}
};

struct RawMessageDeactivateFirewall : public RawMessageClientAction 
{
	inline void Init(UInt32 messageId)
	{
		RawMessageClientAction::Init(sizeof(RawMessageDeactivateFirewall), MessageTypeDeactivateFirewall, messageId);
	}
};

struct RawMessageSubscribeAsaProviderOfRules : public RawMessageClientAction 
{
	inline void Init(UInt32 messageId)
	{
		RawMessageClientAction::Init(sizeof(RawMessageSubscribeAsaProviderOfRules), MessageTypeSubscribeAsaProviderOfRules, messageId);
	}
};

struct RawMessageUnsubscribeAsaProviderOfRules : public RawMessageClientAction  
{
	inline void Init(UInt32 messageId)
	{
		RawMessageClientAction::Init(sizeof(RawMessageUnsubscribeAsaProviderOfRules), MessageTypeUnsubscribeAsaProviderOfRules, messageId);
	}
};

struct RawMessageSubscribeToInfoRules : public RawMessageClientAction  
{
	inline void Init(UInt32 messageId)
	{
		RawMessageClientAction::Init(sizeof(RawMessageSubscribeToInfoRules), MessageTypeSubscribeToInfoRules, messageId);
	}
};

struct RawMessageUnsubscribeFromInfoRules : public RawMessageClientAction  
{
	inline void Init(UInt32 messageId)
	{
		RawMessageClientAction::Init(sizeof(RawMessageUnsubscribeFromInfoRules), MessageTypeUnsubscribeFromInfoRules, messageId);
	}
};

struct RawMessageSubscribeToInfoSockets : public RawMessageClientAction  
{
	inline void Init(UInt32 messageId)
	{
		RawMessageClientAction::Init(sizeof(RawMessageSubscribeToInfoSockets), MessageTypeSubscribeToInfoSockets, messageId);
	}
};

struct RawMessageUnsubscribeFromInfoSockets : public RawMessageClientAction  
{
	inline void Init(UInt32 messageId)
	{
		RawMessageClientAction::Init(sizeof(RawMessageUnsubscribeFromInfoSockets), MessageTypeUnsubscribeFromInfoSockets, messageId);
	}
};

#endif
