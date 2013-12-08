//
//	yafw.h
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

#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kernel_types.h>

#include <sys/kpi_socket.h>
#include <sys/kpi_socketfilter.h>
#include <netinet/in.h>

#ifndef yafw_yafw_h
#define yafw_yafw_h

#define FIREGATE_BOOL			int
#define FIREGATE_TRUE			1
#define FIREGATE_FALSE			0
#define FIREGATE_APPLE_HANDLE	0x55495354		// UIST ( ~ UIST + 6 ) Total 7 sequential registrations
#define FIREGATE_BUNDLEID		"com.yonketa.yafw.kext"

kern_return_t yafw_start(kmod_info_t * ki, void *d);
kern_return_t yafw_stop(kmod_info_t *ki, void *d);
void yafw_log(int level, const char * message, ...) __printflike(2,3);

extern struct sflt_filter yafw_inet_filter;
extern int yafw_verbosity;

struct yafw_protocol {
	sflt_handle handle;
	int domain;
	int type;
	int protocol;
	int state;
};

#endif
