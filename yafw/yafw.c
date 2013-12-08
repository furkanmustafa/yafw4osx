//
//  yafw.c
//
//	YAFW is free software: you can redistribute it and/or modify
//	it under the terms of the GNU General Public License as published by
//	the Free Software Foundation, either version 3 of the License, or
//	(at your option) any later version.
//
//	YAFW is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU General Public License for more details.
//
//	You should have received a copy of the GNU General Public License
//	along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//  Furkan Mustafa on 09/12/13. Copyright (c) 2013 yonketa.
//
//	Uses Partial Code/Stuff from https://code.google.com/p/watchfirewall/
//		Copyright 2009 __MoonLight__. All rights reserved.
//

#include "yafw.h"
#include "filters.h"

struct yafw_protocol yafw_protocols[] = {
	{ FIREGATE_APPLE_HANDLE, PF_INET, SOCK_STREAM, IPPROTO_TCP, 0 },
	{ FIREGATE_APPLE_HANDLE + 1, PF_INET, SOCK_DGRAM, IPPROTO_UDP, 0 },
	{ FIREGATE_APPLE_HANDLE + 2, PF_INET, SOCK_RAW, IPPROTO_ICMP, 0 },
	{ FIREGATE_APPLE_HANDLE + 3, PF_INET6, SOCK_STREAM, IPPROTO_TCP, 0 },
	{ FIREGATE_APPLE_HANDLE + 4, PF_INET6, SOCK_DGRAM, IPPROTO_UDP, 0 },
	{ FIREGATE_APPLE_HANDLE + 5, PF_INET6, SOCK_RAW, IPPROTO_ICMP, 0 }/*,
	{ FIREGATE_APPLE_HANDLE + 6, PF_UNIX, SOCK_STREAM, 0, 0 }*/
};

struct sflt_filter yafw_inet_filter;
int yafw_verbosity = 0;

void yafw_log(int level, const char * format, ...) {
	if (level > yafw_verbosity) return;
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
}

errno_t yafw_clean_filters() {
	errno_t error = 0;
	
	size_t len_protocols = sizeof(yafw_protocols) / sizeof(*yafw_protocols);
	for (int i = 0; i < len_protocols; i++) {
		if (!yafw_protocols[i].state) continue; // already clean.
		
		yafw_inet_filter.sf_handle = yafw_protocols[i].handle;
		error = sflt_unregister(yafw_inet_filter.sf_handle);
		if (error != KERN_SUCCESS)
			yafw_protocols[i].state = 0;
		else
			return error; // failed, !HARDFAIL
	}
	
	return error;
}
errno_t yafw_setup_filters() {
	errno_t error = 0;
	
	yafw_inet_filter = (struct sflt_filter){
		FIREGATE_APPLE_HANDLE,
		SFLT_GLOBAL | SFLT_EXTENDED,/* sf_flags */
		(char*)FIREGATE_BUNDLEID,   /* sf_name - cannot be nil else param err results */
		yafw_unregistered,               /* sf_unregistered_func */
		yafw_attach,                     /* sf_attach_func - cannot be nil else param err results */
		yafw_detach,                     /* sf_detach_func - cannot be nil else param err results */
		yafw_notify,                     /* sf_notify_func */
		yafw_getpeername,                /* sf_getpeername_func */
		yafw_getsockname,            /* sf_getsockname_func */
		yafw_dataIn,                 /* sf_data_in_func */
		yafw_dataOut,                /* sf_data_out_func */
		yafw_connectIn,              /* sf_connect_in_func */
		yafw_connectOut,             /* sf_connect_out_func */
		yafw_bind,                   /* sf_bind_func */
		yafw_setoption,              /* sf_setoption_func */
		yafw_getoption,              /* sf_getoption_func */
		yafw_listen,                 /* sf_listen_func */
		yafw_ioctl,                  /* sf_ioctl_func */
		{sizeof(struct sflt_filter_ext),
			yafw_accept, {NULL,NULL,NULL,NULL,NULL}} /*sf_filter_ext */
	};
	
	size_t len_protocols = sizeof(yafw_protocols) / sizeof(*yafw_protocols);
	for (int i = 0; i < len_protocols; i++) {
		yafw_inet_filter.sf_handle = yafw_protocols[i].handle;
		error = sflt_register(&yafw_inet_filter, yafw_protocols[i].domain, yafw_protocols[i].type, yafw_protocols[i].protocol);
		if (!error)
			yafw_protocols[i].state = 1;
		else
			return error; // failed, !NEEDS ROLLBACK for succeeded registers
	}
	
	return error;
}

kern_return_t yafw_start(kmod_info_t * ki, void *d) {
	yafw_log(0, "YAFW - Copyright (C) 2013 UI STUDIO GK - JAPAN\n"
				 "\tThis program comes with ABSOLUTELY NO WARRANTY;\n"
				 "\tThis is free software, and you are welcome to redistribute it\n"
				 "\tunder certain conditions; see http://www.gnu.org/licenses/gpl.txt for details.\n");
	
	yafw_log(1, "YAFW Network Layer Loading: ");
	
	errno_t error = yafw_setup_filters();
	if (error != KERN_SUCCESS) {
		yafw_log(1, "Cannot Setup Socket Filtering");
		yafw_log(2, ": Error No %d", error);
		yafw_log(1, "\n");
		
		// cleanup
		yafw_clean_filters();
		return KERN_FAILURE;
	}
	
	printf("Done\n");
    return KERN_SUCCESS;
}
kern_return_t yafw_stop(kmod_info_t *ki, void *d) {
	printf("YAFW Network Layer Unloading: ");
	
	if (yafw_clean_filters() != KERN_SUCCESS) {
		printf("Couldn't Cleanup Properly\n");
		return KERN_FAILURE;
	}
	
	printf("Done\n");
    return KERN_SUCCESS;
}
