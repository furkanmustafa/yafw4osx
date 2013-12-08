#include "messages.h"
#include "messageType.h"

Message*
Message::CreateText(const char* format,...)
{
    va_list argList;
	
    if (!format)
        return 0;

	Message *message = new(255 + sizeof(RawMessageBase)) Message;
	
	if(!message)
		return NULL;
	
    va_start(argList, format);
	
    message->raw.size = vsnprintf((char*)&message->raw + sizeof(RawMessageBase), 254, format, argList) + sizeof(RawMessageBase) + 1;

    va_end (argList);

	message->raw.type = MessageTypeText;
	message->references = 1;
	
    return message;
}

SInt32 nextTextMessage;//TODO: only for debug

Message*
Message::CreateTextFromCookie(const char* message, SocketCookie* cookie)
{
	UInt64 time;
	clock_get_uptime(&time);
	UInt32 mc = OSIncrementAtomic(&nextTextMessage);
	return CreateText("%d %lld %11s %20s path: %s  so: %9d  pid: %3d  uid: %3d  domain: %3d  type: %3d  protocol: %3d", 
					  mc,
					  time,
					  message, 
					  cookie->application->processName->getCStringNoCopy(),
					  cookie->application->filePath->getCStringNoCopy(),
					  cookie->socket, 
					  cookie->application->pid, 
					  cookie->application->uid,
					  cookie->sockDomain,
					  cookie->sockType,
					  cookie->sockProtocol);
}

Message*	
Message::CreateSfltUnregistered()//??????
{
	Message *message = new(sizeof(RawMessageSfltUnregistered)) Message;
	if(message)
	{
		RawMessageSfltUnregistered* rawMessage = (RawMessageSfltUnregistered*)&message->raw;
		rawMessage->Init();
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltAttach(pid_t pid, uid_t uid, socket_t so, int proto)
{
	Message *message = new(sizeof(RawMessageSfltAttach)) Message;
	if(message)
	{
		RawMessageSfltAttach* rawMessage = (RawMessageSfltAttach*)&message->raw;
		rawMessage->Init(pid, uid, (UInt64)so, proto);
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltDetach(pid_t pid, uid_t uid, socket_t so)
{
	Message *message = new(sizeof(RawMessageSfltDetach)) Message;
	if(message)
	{
		RawMessageSfltDetach* rawMessage = (RawMessageSfltDetach*)&message->raw;
		rawMessage->Init(pid, uid, (UInt64)so);
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltNotify(pid_t pid, uid_t uid, socket_t so, UInt16 event)
{
	Message *message = new(sizeof(RawMessageSfltNotify)) Message;
	if(message)
	{
		RawMessageSfltNotify* rawMessage = (RawMessageSfltNotify*)&message->raw;
		rawMessage->Init(pid, uid, (UInt64)so, event);
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltGetPeerName(pid_t pid, uid_t uid, socket_t so, sockaddr *sa)
{
	size_t neededSize = RawMessageSfltGetPeerName::GetNeededSize((SockAddress*)sa);
	Message *message = new(neededSize) Message;
	if(message)
	{
		RawMessageSfltGetPeerName* rawMessage = (RawMessageSfltGetPeerName*)&message->raw;
		rawMessage->Init(neededSize, pid, uid, (UInt64)so, (SockAddress*)sa);
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltGetSockName(pid_t pid, uid_t uid, socket_t so, sockaddr *sa)
{
	size_t neededSize = RawMessageSfltGetSockName::GetNeededSize((SockAddress*)sa);
	Message *message = new(neededSize) Message;
	if(message)
	{
		RawMessageSfltGetSockName* rawMessage = (RawMessageSfltGetSockName*)&message->raw;
		rawMessage->Init(neededSize, pid, uid, (UInt64)so, (SockAddress*)sa);
		message->references = 1;
	}
	return message;
}


Message*	
Message::CreateSfltDataIn(pid_t pid, uid_t uid, socket_t so, int proto, const sockaddr *from)
{
	size_t neededSize = RawMessageSfltDataIn::GetNeededSize((SockAddress*)from);
	Message *message = new(neededSize) Message;
	if(message)
	{
		RawMessageSfltDataIn* rawMessage = (RawMessageSfltDataIn*)&message->raw;
		rawMessage->Init(neededSize, pid, uid, (UInt64)so, proto, (SockAddress*)from);
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltDataOut(pid_t pid, uid_t uid, socket_t so, int proto, const sockaddr *to)
{
	size_t neededSize = RawMessageSfltDataOut::GetNeededSize((SockAddress*)to);
	Message *message = new(neededSize) Message;
	if(message)
	{
		RawMessageSfltDataOut* rawMessage = (RawMessageSfltDataOut*)&message->raw;
		rawMessage->Init(neededSize, pid, uid, (UInt64)so, proto, (SockAddress*)to);
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltConnectIn(pid_t pid, uid_t uid, socket_t so, const sockaddr *from)
{
	size_t neededSize = RawMessageSfltConnectIn::GetNeededSize((SockAddress*)from);
	Message *message = new(neededSize) Message;
	if(message)
	{
		RawMessageSfltConnectIn* rawMessage = (RawMessageSfltConnectIn*)&message->raw;
		rawMessage->Init(neededSize, pid, uid, (UInt64)so, (SockAddress*)from);
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltConnectOut(pid_t pid, uid_t uid, socket_t so, const sockaddr *to)
{
	size_t neededSize = RawMessageSfltConnectOut::GetNeededSize((SockAddress*)to);
	Message *message = new(neededSize) Message;
	if(message)
	{
		RawMessageSfltConnectOut* rawMessage = (RawMessageSfltConnectOut*)&message->raw;
		rawMessage->Init(neededSize, pid, uid, (UInt64)so, (SockAddress*)to);
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltBind(pid_t pid, uid_t uid, socket_t so, const sockaddr *to)
{
	size_t neededSize = RawMessageSfltBind::GetNeededSize((SockAddress*)to);
	Message *message = new(neededSize) Message;
	if(message)
	{
		RawMessageSfltBind* rawMessage = (RawMessageSfltBind*)&message->raw;
		rawMessage->Init(neededSize, pid, uid, (UInt64)so, (SockAddress*)to);
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltSetOption(pid_t pid, uid_t uid, socket_t so, sockopt_t opt)
{
	Message *message = new(sizeof(RawMessageSfltSetOption)) Message;
	if(message)
	{
		RawMessageSfltSetOption* rawMessage = (RawMessageSfltSetOption*)&message->raw;
		rawMessage->Init(pid, uid, (UInt64)so, sockopt_name(opt));
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltGetOption(pid_t pid, uid_t uid, socket_t so, sockopt_t opt)
{
	Message *message = new(sizeof(RawMessageSfltGetOption)) Message;
	if(message)
	{
		RawMessageSfltGetOption* rawMessage = (RawMessageSfltGetOption*)&message->raw;
		rawMessage->Init(pid, uid, (UInt64)so, sockopt_name(opt));
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltListen(pid_t pid, uid_t uid, socket_t so)
{
	Message *message = new(sizeof(RawMessageSfltListen)) Message;
	if(message)
	{
		RawMessageSfltListen* rawMessage = (RawMessageSfltListen*)&message->raw;
		rawMessage->Init(pid, uid, (UInt64)so);
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltIoctl(pid_t pid, uid_t uid, socket_t so, UInt32 request, const char* argp)
{
	Message *message = new(sizeof(RawMessageSfltIoctl)) Message;
	if(message)
	{
		RawMessageSfltIoctl* rawMessage = (RawMessageSfltIoctl*)&message->raw;
		rawMessage->Init(pid, uid, (UInt64)so, request);
		message->references = 1;
	}
	return message;
}

Message*	
Message::CreateSfltAccept(pid_t pid, uid_t uid, socket_t so_listen, socket_t so, const sockaddr *local, const sockaddr *remote)
{
	size_t neededSize = RawMessageSfltAccept::GetNeededSize((SockAddress*)local, (SockAddress*)remote);
	Message *message = new(neededSize) Message;
	if(message)
	{
		RawMessageSfltAccept* rawMessage = (RawMessageSfltAccept*)&message->raw;
		rawMessage->Init(neededSize, pid, uid, (UInt64)so_listen, (UInt64)so, (SockAddress*)local, (SockAddress*)remote);
		message->references = 1;
	}
	return message;
}

Message*
Message::CreateRequestRule(char* processName, char* filePath, UInt16 sockDomain, UInt16 sockType, UInt16 sockProtocol,	sockaddr* sockAddress, UInt8 direction,
					   pid_t pid, uid_t uid)
{
	//TODO: implement
	return NULL;
}

Message*
Message::CreateRuleAdded(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState, UInt32 ruleId)
{
	Message* message = new (sizeof(RawMessageRuleAdded)) Message;
	if(message)
	{
		((RawMessageRuleAdded*)&message->raw)->Init(unitId, clientMessageId, actionState, ruleId);
		message->references = 1;
	}
	
	return message;
}

Message* 
Message::CreateRuleDeleted(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState, UInt32 ruleId)
{
	Message* message = new (sizeof(RawMessageRuleDeleted)) Message;
	if(message)
	{
		((RawMessageRuleDeleted*)&message->raw)->Init(unitId, clientMessageId, actionState, ruleId);
		message->references = 1;
	}
	
	return message;
}

Message*
Message::CreateRuleActivated(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState, UInt32 ruleId)
{
	Message* message = new (sizeof(RawMessageRuleActivated)) Message;
	if(message)
	{
		((RawMessageRuleActivated*)&message->raw)->Init(unitId, clientMessageId, actionState, ruleId);
		message->references = 1;
	}
	
	return message;
}

Message*
Message::CreateRuleDeactivated(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState, UInt32 ruleId)
{
	Message* message = new (sizeof(RawMessageRuleDeactivated)) Message;
	if(message)
	{
		((RawMessageRuleDeactivated*)&message->raw)->Init(unitId, clientMessageId, actionState, ruleId);
		message->references = 1;
	}
	
	return message;
}

Message*
Message::CreateSocketData(UInt8 direction, UInt8 stateOperation, UInt32 stateByRuleId, pid_t pid, uid_t uid, socket_t so, UInt32 packets, UInt32 bytes, sockaddr *from, sockaddr *to, OSString *processName)
{
	//calculate size
	int neddedSize = sizeof(RawMessageSocketData);//- 3
	int processNameSize = 0;
	const char *processNameC = NULL;
	
	if(from != NULL)
		neddedSize += from->sa_len;
	
	if(to != NULL)
		neddedSize += to->sa_len;
	
	if(processName != NULL)
	{
		processNameSize = processName->getLength();
		processNameC = processName->getCStringNoCopy();
		neddedSize += processNameSize;
	}
	
	//TODO: is real
	Message* message = new(neddedSize) Message; 
	if(message)
	{
		((RawMessageSocketData*)&message->raw)->Init(neddedSize, direction, stateOperation, stateByRuleId, pid, uid, (UInt64)so, packets, bytes, (SockAddress*)from, (SockAddress*)to, processNameC, processNameSize);
		message->references = 1;
	}
	
	return message;
}

//TODO: additional info: from who
Message*
Message::CreateSocketOpen(socket_t so)
{
	Message *message = new(sizeof(RawMessageSocketOpen)) Message;
	if(message)
	{
		RawMessageSocketOpen* rawMessage = (RawMessageSocketOpen*)&message->raw;
		rawMessage->Init((UInt64)so);
		message->references = 1;
	}
	return message;
}

Message*
Message::CreateSocketClosed(socket_t so)
{
	Message *message = new(sizeof(RawMessageSocketClosed)) Message;
	if(message)
	{
		RawMessageSocketClosed* rawMessage = (RawMessageSocketClosed*)&message->raw;
		rawMessage->Init((UInt64)so);
		message->references = 1;
	}
	return message;
}

Message*
Message::CreateFirewallActivated(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
{
	Message *message = new (sizeof(RawMessageFirewallActivated)) Message;
	if(message)
	{
		((RawMessageFirewallActivated*)&message->raw)->Init(unitId, clientMessageId, actionState); 
		message->references = 1;
	}
	return message;
}

Message*
Message::CreateFirewallDeactivated(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
{
	Message *message = new (sizeof(RawMessageFirewallDeactivated)) Message;
	if(message)
	{
		((RawMessageFirewallActivated*)&message->raw)->Init(unitId, clientMessageId, actionState);
		message->references = 1;
	}
	return message;
}

Message*
Message::CreateClientSubscribedAsaProviderOfRules(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
{
	Message *message = new (sizeof(RawMessageClientSubscribedAsaProviderOfRules)) Message;
	if(message)
	{
		((RawMessageClientSubscribedAsaProviderOfRules*)&message->raw)->Init(unitId, clientMessageId, actionState);
		message->references = 1;
	}
	return message;
}

Message*
Message::CreateClientUnsubscribedAsaProviderOfRules(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
{
	Message *message = new (sizeof(RawMessageClientUnsubscribedAsaProviderOfRules)) Message;
	if(message)
	{
		((RawMessageClientUnsubscribedAsaProviderOfRules*)&message->raw)->Init(unitId, clientMessageId, actionState);
		message->references = 1;
	}
	return message;
}

Message*
Message::CreateClientSubscribedToInfoRules(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
{
	Message *message = new(sizeof(RawMessageClientSubscribedToInfoRules)) Message;
	if(message)
	{
		RawMessageClientSubscribedToInfoRules* rawMessage = (RawMessageClientSubscribedToInfoRules*)&message->raw;
		rawMessage->Init(unitId, clientMessageId, actionState);
		message->references = 1;
	}
	return message;
}

Message*
Message::CreateClientUnsubscribedFromInfoRules(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
{
	//TODO: size
	Message *message = new(sizeof(RawMessageClientUnsubscribedFromInfoRules)) Message;
	if(message)
	{
		((RawMessageClientUnsubscribedFromInfoRules*)&message->raw)->Init(unitId, clientMessageId, actionState);
		message->references = 1;
	}
	return message;
}

Message*
Message::CreateClientSubscribedToInfoSockets(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
{
	Message *message = new(sizeof(RawMessageClientSubscribedToInfoSockets)) Message;
	if(message)
	{
		((RawMessageClientSubscribedToInfoSockets*)&message->raw)->Init(unitId, clientMessageId, actionState);
		message->references = 1;
	}
	return message;
}

Message*
Message::CreateClientUnsubscribedFromInfoSockets(UInt32 unitId, UInt32 clientMessageId, UInt32 actionState)
{
	Message *message = new (sizeof(RawMessageClientUnsubscribedFromInfoSockets)) Message;
	if(message)
	{
		((RawMessageClientUnsubscribedFromInfoSockets*)&message->raw)->Init(unitId, clientMessageId, actionState);
		message->references = 1;
	}
	return message;
}

Message*
Message::CreateFirewallClosing()
{
	Message *message = new Message();
	if(message)
	{
		RawMessageFirewallClosing* rawMessageFirewallClosing = (RawMessageFirewallClosing*)&message->raw; 
		rawMessageFirewallClosing->Init(); 
		message->references = 1;
	}
	return message;
}
