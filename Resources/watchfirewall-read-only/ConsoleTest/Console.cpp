#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <getopt.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <libkern/OSTypes.h>
#include "ServerConnection.h"

typedef void* socket_t;

#include "messageType.h"
#include "Console.h"
#include "portNames.h"


ServerConnection serverConnection;
char buffer[8*1024];
pthread_mutex_t closeMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t closeCond = PTHREAD_COND_INITIALIZER;
bool userClosed = false;


const char* getSockIoctlRequestName(uint32_t option)
{
	//SO_REUSEPORT
	//FIONBIO
}

const char* getSockStateName(uint32_t state)
{
	switch(state)
	{
		case 1:  return "connecting"; 
		case 2:	 return "connected"; 
		case 3:  return "disconnecting";
		case 4:  return	"disconnected";
		case 5:  return	"flush_read";
		case 6:  return	"shutdown"; /* param points to an integer specifying how (read, write, or both) see man 2 shutdown */
		case 7:  return "cantrecvmore";
		case 8:  return	"cantsendmore";
		case 9:  return	"closing"; 
		case 10: return	"bound"; 
			
		default:
			return "";
	}
}

const char* getOptionName(uint32_t option)
{
	switch (option)
	{
		case SO_BROADCAST: return "BROADCAST";
		case SO_OOBINLINE: return "OOBINLINE";
		case SO_DEBUG: return "DEBUG";
		case SO_REUSEADDR: return "REUSEADDR";
		case SO_REUSEPORT: return "REUSEPORT";
		case SO_KEEPALIVE: return "KEEPALIVE";
		case SO_DONTROUTE: return "DONTROUTE";
		case SO_LINGER: return "LINGER"; 
		case SO_LINGER_SEC: return "LINGER_SEC";
		case SO_SNDBUF: return "SNDBUF";
		case SO_RCVBUF: return "RCVBUF";
		case SO_SNDLOWAT: return "SNDLOWAT";
		case SO_RCVLOWAT: return "RCVLOWAT";
		case SO_SNDTIMEO: return "SNDTIMEO";
		case SO_RCVTIMEO: return "RCVTIMEO";
		case SO_NOSIGPIPE: return "NOSIGPIPE";
		case SO_TYPE: return "TYPE";
		case SO_ERROR: return "ERROR";
		case SO_NREAD: return "NREAD";
		case SO_NWRITE: return "NWRITE";	
			/////end new
		default:        // unknown option name - result = no string
			return  "UNKNOWN OPTION";
			            
	}
}

const char* getSockFamilyName(uint8_t fn)
{
	switch (fn) 
	{
		case	AF_UNSPEC:/* unspecified */
			return "UNSPEC";		
		
		case	AF_UNIX:/* local to host (pipes) */
			return "UNIX/LOCAL";

		case	AF_INET:/* internetwork: UDP, TCP, etc. */
			return "INET";		

		case	AF_IMPLINK:/* arpanet imp addresses */
			return "IMPLINK";
			
		case	AF_PUP:/* pup protocols: e.g. BSP */
			return "PUP";
			
		case	AF_CHAOS:/* mit CHAOS protocols */
			return "CHAOS";
			
		case	AF_NS:/* XEROX NS protocols */
			return "XEROX NS";

		case	AF_ISO:/* ISO protocols */
			return "ISO/OSI";

		case	AF_ECMA:/* European computer manufacturers */
			return "ECMA";

		case	AF_DATAKIT:/* datakit protocols */
			return "DATAKIT";

		case	AF_CCITT:/* CCITT protocols, X.25 etc */
			return "CCITT";

		case	AF_SNA:/* IBM SNA */
			return "SNA";

		case	AF_DECnet:/* DECnet */
			return "DECnet";

		case	AF_DLI:/* DEC Direct data link interface */
			return "DLI";

		case	AF_LAT:/* LAT */
			return "LAT";

		case	AF_HYLINK:/* NSC Hyperchannel */
			return "HYLINK";

		case	AF_APPLETALK:/* Apple Talk */
			return "APPLETALK";

		case	AF_ROUTE:/* Internal Routing Protocol */
			return "ROUTE";

		case	AF_LINK:/* Link layer interface */
			return "LINK";

		case	pseudo_AF_XTP:/* eXpress Transfer Protocol (no AF) */
			return "pseudo_XTP";

		case	AF_COIP:/* connection-oriented IP, aka ST II */
			return "COIP";

		case	AF_CNT:/* Computer Network Technology */
			return "CNT";

		case	pseudo_AF_RTIP:/* Help Identify RTIP packets */
			return "pseudo_RTIP";

		case	AF_IPX:/* Novell Internet Protocol */
			return "IPX";

		case	AF_SIP:/* Simple Internet Protocol */
			return "SIP";

		case	pseudo_AF_PIP:/* Help Identify PIP packets */
			return "pseudo_PIP";

		case	AF_NDRV:/* Network Driver 'raw' access */
			return "NDRV";

		case	AF_ISDN:/* Integrated Services Digital Network*/ /* CCITT E.164 recommendation */
			return "ISDN/E164";

		case	pseudo_AF_KEY:/* Internal key-management function */
			return "pseudo_KEY";

		case	AF_INET6:/* IPv6 */
			return "INET6";

		case	AF_NATM:/* native ATM access */
			return "NATM";

		case	AF_SYSTEM:/* Kernel event messages */
			return "SYSTEM";

		case	AF_NETBIOS:/* NetBIOS */
			return "NETBIOS";

		case	AF_PPP:/* PPP communication protocol */
			return "PPP";

		case	pseudo_AF_HDRCMPLT:/* Used by BPF to not rewrite headers in interface output routine*/
			return "pseudo_HDRCMPLT";

		case	AF_RESERVED_36:/* Reserved for internal usage */
			return "RESERVED_36";

		case	AF_MAX:
			return "MAX";

		default:
			return "";
	}
}

void printfSockaddr(const struct sockaddr *sa)
{
	if(!sa || sa->sa_family == AF_UNSPEC)
	{
		printf("undefined  ");
		return ;
	}
	
	printf("family: %d(%s)  ", sa->sa_family, getSockFamilyName(sa->sa_family));
	char s[255]={0};
    switch(sa->sa_family) 
	{
        case AF_INET:
		{
			sockaddr_in *sa_in = (sockaddr_in*)sa;
            inet_ntop(AF_INET, &sa_in->sin_addr, s, 254);
			uint16_t port = ntohs(sa_in->sin_port);
			printf("address: %s  port: %d(%s)  ", s, port, getPortName(port));

            break;
		}	

        case AF_INET6:
		{
			sockaddr_in6 *sa_in6 =  (sockaddr_in6 *)sa;
            inet_ntop(AF_INET6, &sa_in6->sin6_addr, s, 254);
			uint16_t port = ntohs(sa_in6->sin6_port);
			printf("address: %s  port: %d(%s)  ", s, port, getPortName(port));
			
            break;
		}	
        default:
            printf("address unsuported  ");
    }
}

/*
 SignalHandler - implemented to handle an interrupt from the command line using Ctrl-C.
 */
static void SignalHandler(int sigraised)
{
	userClosed = true;
	serverConnection.Close();
    //_exit(0);
}

static void CloseHandle(const ServerConnection *conn)
{
	printf("close handle invoked\n");
	pthread_cond_broadcast(&closeCond);
}

static void ReciveMessageHandler(const RawMessageBase *message)
{
	if(!message) return;
		
	switch (message->type) 
	{
		case MessageTypeText:
		{
			RawMessageText* messageText = (RawMessageText*)message;
			printf("%s \n", messageText->textBuffer);
		}
			break;
			
		case MessageTypeRequestRule:
		{
			RawMessageRequestRule* messageRequestRule = (RawMessageRequestRule*)message;
		}
			break;
			
		case MessageTypeRuleAdded:
		{
			RawMessageRuleAdded* messageRuleAdded = (RawMessageRuleAdded*)message;
		}
			break;
			
		case MessageTypeRuleDeleted:
		{
			RawMessageRuleDeleted* messageRuleDeleted = (RawMessageRuleDeleted*)message;
		}
			break;
			
		case MessageTypeRuleDeactivated:
		{
			RawMessageRuleDeactivated* messageRuleDeactivated = (RawMessageRuleDeactivated*)message;
		}
			break;
			
		case MessageTypeRuleActivated:
		{
			RawMessageRuleActivated* messageRuleActivated = (RawMessageRuleActivated*)message;
		}
			break;
			
		case MessageTypeSocketData:
		{
			RawMessageSocketData* messageSocketData = (RawMessageSocketData*)message;
		}
			break;
			
		case MessageTypeSocketOpen:
		{
			RawMessageSocketOpen* messageSocketOpen = (RawMessageSocketOpen*)message;
		}
			break;
			
		case MessageTypeSocketClosed:
		{
			RawMessageSocketClosed* messageSocketClosed = (RawMessageSocketClosed*)message;
		}
			break;
			
		case MessageTypeFirewallActivated:
		{
			RawMessageFirewallActivated* messageFirewallActivated = (RawMessageFirewallActivated*)message;
		}
			break;
			
		case MessageTypeFirewallDeactivated:
		{
			RawMessageFirewallDeactivated* messageFirewallDeactivated = (RawMessageFirewallDeactivated*)message;
		}
			break;
			
			
		case MessageTypeClientSubscribedAsaProviderOfRules:
		{
			RawMessageClientSubscribedAsaProviderOfRules* messageRegistredForAsk = (RawMessageClientSubscribedAsaProviderOfRules*)message;
		}
			break;
			
		case MessageTypeClientUnsubscribedAsaProviderOfRules:
		{
			RawMessageClientUnsubscribedAsaProviderOfRules* messageUnregistredAsk = (RawMessageClientUnsubscribedAsaProviderOfRules*)message;
		}
			break;
			
		case MessageTypeClientSubscribedToInfoRules:
		{
			RawMessageClientSubscribedToInfoRules* messageRegistredForInfoRule = (RawMessageClientSubscribedToInfoRules*)message;
		}
			break;
			
		case MessageTypeClientUnsubscribedFromInfoRules:
		{
			RawMessageClientUnsubscribedFromInfoRules* messageUnregistredInfoRule = (RawMessageClientUnsubscribedFromInfoRules*)message;
		}
			break;
			
		case MessageTypeClientSubscribedToInfoSockets:
		{
			RawMessageClientSubscribedToInfoSockets* messageRegistredForInfoSocket = (RawMessageClientSubscribedToInfoSockets*)message;
			printf("client registred for info rule: %s", messageRegistredForInfoSocket->actionState ? "success" : "error");
		}
			break;
			
		case MessageTypeClientUnsubscribedFromInfoSockets:
		{
			RawMessageClientUnsubscribedFromInfoSockets* messageUnregistredInfoSocket = (RawMessageClientUnsubscribedFromInfoSockets*)message;
		}
			break;
			
			
			//begin debug output
		case MessageTypeSfltAttach:
		{
			RawMessageSfltAttach *rawMessage = (RawMessageSfltAttach*)message;
			
			printf("attach       -> pid: %-4lu  uid: %-4lu so: %-12llu  proto: %4u\n",rawMessage->pid, rawMessage->uid, rawMessage->so, rawMessage->proto);
		}
			break;
		case MessageTypeSfltDetach:
		{
			RawMessageSfltDetach *rawMessage = (RawMessageSfltDetach*)message;
			
			printf("deatch       -> pid: %-4lu  uid: %-4lu so: %-12llu\n",rawMessage->pid, rawMessage->uid, rawMessage->so);
		}
			break;
			
		case MessageTypeSfltNotify:
		{
			RawMessageSfltNotify *rawMessage = (RawMessageSfltNotify*)message;
			
			printf("notify       -> pid: %-4lu  uid: %-4lu so: %-12llu  event: %u(%s)\n",rawMessage->pid, rawMessage->uid, rawMessage->so, rawMessage->event, getSockStateName(rawMessage->event));
		}
			break;
			
		case MessageTypeSfltGetPeerName:
		{
			RawMessageSfltGetPeerName *rawMessage = (RawMessageSfltGetPeerName*)message;
			
			printf("get peer name-> pid: %-4lu  uid: %-4lu so: %-12llu  sa: ",rawMessage->pid, rawMessage->uid, rawMessage->so);
			printfSockaddr((sockaddr*)&rawMessage->sa);
			printf("\n");
		}
			break;
			
		case MessageTypeSfltGetSockName:
		{
			RawMessageSfltGetSockName *rawMessage = (RawMessageSfltGetSockName*)message;
			
			printf("get sock name-> pid: %-4lu  uid: %-4lu so: %-12llu  sa: ",rawMessage->pid, rawMessage->uid, rawMessage->so);
			printfSockaddr((sockaddr*)&rawMessage->sa);
			printf("\n");
		}
			break;
			
		case MessageTypeSfltDataIn:
		{
			RawMessageSfltDataIn *rawMessage = (RawMessageSfltDataIn*)message;
			
			printf("data in      -> pid: %-4lu  uid: %-4lu so: %-12llu  proto: %4u  from: ",rawMessage->pid, rawMessage->uid, rawMessage->so, rawMessage->proto);
			printfSockaddr((sockaddr*)&rawMessage->from);
			printf("\n");
		}
			break;
			
		case MessageTypeSfltDataOut:
		{
			RawMessageSfltDataOut *rawMessage = (RawMessageSfltDataOut*)message;
			
			printf("data out     -> pid: %-4lu  uid: %-4lu so: %-12llu  proto: %4u  to  : ",rawMessage->pid, rawMessage->uid, rawMessage->so, rawMessage->proto);
			printfSockaddr((sockaddr*)&rawMessage->to);
			printf("\n");
		}
			break;
			
		case MessageTypeSfltConnectIn:
		{
			RawMessageSfltConnectIn *rawMessage = (RawMessageSfltConnectIn*)message;
			
			printf("connect in   -> pid: %-4lu  uid: %-4lu so: %-12llu  from: ",rawMessage->pid, rawMessage->uid, rawMessage->so);
			printfSockaddr((sockaddr*)&rawMessage->from);
			printf("\n");
		}
			break;
			
		case MessageTypeSfltConnectOut:
		{
			RawMessageSfltConnectOut *rawMessage = (RawMessageSfltConnectOut*)message;
			
			printf("connect out  -> pid: %-4lu  uid: %-4lu so: %-12llu  to: ",rawMessage->pid, rawMessage->uid, rawMessage->so);
			printfSockaddr((sockaddr*)&rawMessage->to);
			printf("\n");
		}
			break;
			
		case MessageTypeSfltBind:
		{
			RawMessageSfltBind *rawMessage = (RawMessageSfltBind*)message;
			
			printf("bind         -> pid: %-4lu  uid: %-4lu so: %-12llu  to: ",rawMessage->pid, rawMessage->uid, rawMessage->so);
			printfSockaddr((sockaddr*)&rawMessage->to);
			printf("\n");
		}
			break;
			
		case MessageTypeSfltSetOption:
		{
			RawMessageSfltSetOption *rawMessage = (RawMessageSfltSetOption*)message;
			
			printf("set option   -> pid: %-4lu  uid: %-4lu so: %-12llu  opt: Ox%04x(%s) \n",rawMessage->pid, rawMessage->uid, rawMessage->so, (unsigned)rawMessage->optionName, getOptionName(rawMessage->optionName));
		}
			break;
			
		case MessageTypeSfltGetOption:
		{
			RawMessageSfltGetOption *rawMessage = (RawMessageSfltGetOption*)message;
			
			printf("get option   -> pid: %-4lu  uid: %-4lu so: %-12llu  opt: 0x%04x(%s) \n",rawMessage->pid, rawMessage->uid, rawMessage->so, (unsigned)rawMessage->optionName, getOptionName(rawMessage->optionName));
		}
			break;
			
		case MessageTypeSfltListen:
		{
			RawMessageSfltListen *rawMessage = (RawMessageSfltListen*)message;
			
			printf("listen       -> pid: %-4lu  uid: %-4lu so: %-12llu \n",rawMessage->pid, rawMessage->uid, rawMessage->so);
		}
			break;
			
		case MessageTypeSfltIoctl:
		{
			RawMessageSfltIoctl *rawMessage = (RawMessageSfltIoctl*)message;
			printf("ioctl        -> pid: %-4lu  uid: %-4lu so: %-12llu \n",rawMessage->pid, rawMessage->uid, rawMessage->so);
		}
			break;
			
		case MessageTypeSfltAccept:
		{
			RawMessageSfltAccept *rawMessage = (RawMessageSfltAccept*)message;
			
			printf("accept       -> pid: %-4lu  uid: %-4lu so: %-12llu  soListen: %llu  local: ",rawMessage->pid, rawMessage->uid, rawMessage->so, rawMessage->soListen);
			printfSockaddr((sockaddr*)rawMessage->GetLocal());
			printf("remote: ");
			printfSockaddr((sockaddr*)rawMessage->GetRemote());
			printf("\n");
		}
			break;
			//end debug ouput
			
		case MessageTypeFirewallClosing:
			printf("Connection Closing \n");
			break;
		default:
			break;
	}
	
}

int main()
{	
	sig_t oldHandler = signal(SIGINT, SignalHandler);
    if (oldHandler == SIG_ERR)
        printf("Could not establish new signal handler SIGINT\n");

	oldHandler = signal(SIGTSTP, SignalHandler);
    if (oldHandler == SIG_ERR)
        printf("Could not establish new signal handler SIGSTP\n");
	
	
	while(1)
	{
		if(serverConnection.Open(&ReciveMessageHandler, &CloseHandle))
		{
			printf("connection opened\n");
			pthread_mutex_lock(&closeMutex);
			pthread_cond_wait(&closeCond, &closeMutex);
			
			pthread_mutex_unlock(&closeMutex);
			printf("Connection Closed \n");
			
			if(userClosed)
				break;
		}
		
		sleep(1);
	}
	
	pthread_cond_destroy(&closeCond);
	pthread_mutex_destroy(&closeMutex);
	
	return 0;
}