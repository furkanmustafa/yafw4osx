#include <IOKit/IOLib.h>
#include "firewall.h"

#pragma mark kext routine

extern "C" 
{

	kern_return_t 
	watch_start (kmod_info_t * ki, void * d)
	{	
		//new(&firewall) Firewall;
		IOLog("watch started.\n");
		return firewall.Init() ? KERN_SUCCESS : KERN_FAILURE;
	}


	kern_return_t 
	watch_stop (kmod_info_t * ki, void * d) 
	{
		return firewall.Free() ? KERN_SUCCESS : EBUSY;
	}

}