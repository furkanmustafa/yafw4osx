//
//  filters.c
//
//	Firegate is free software: you can redistribute it and/or modify
//	it under the terms of the GNU General Public License as published by
//	the Free Software Foundation, either version 3 of the License, or
//	(at your option) any later version.
//
//	Firegate is distributed in the hope that it will be useful,
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

#include "filters.h"

void yafw_unregistered(sflt_handle handle) {
	
}

/*	attach function runs in the calling apps context
	thanks: John Colanduoni
	http://stackoverflow.com/questions/11622079/get-owner-of-socket-in-os-x-kernel-extension */
errno_t yafw_attach(void **cookie, socket_t so) {
	// app_pid = proc_selfpid()
	return KERN_SUCCESS;
}
void yafw_detach(void *cookie, socket_t so) {
	
}
void yafw_notify(void *cookie, socket_t so, sflt_event_t event, void *param) {
	
}
int yafw_getpeername(void *cookie, socket_t so, struct sockaddr **sa) {
	
	return KERN_SUCCESS;
}
int yafw_getsockname(void *cookie, socket_t so, struct sockaddr **sa) {
	
	return KERN_SUCCESS;
}
errno_t yafw_dataIn(void *cookie, socket_t so, const struct sockaddr *from, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags) {
	
	return KERN_SUCCESS;
}
errno_t yafw_dataOut(void *cookie, socket_t so, const struct sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags) {
	
	return KERN_SUCCESS;
}
errno_t yafw_connectIn(void *cookie, socket_t so, const struct sockaddr *from) {
	
	return KERN_SUCCESS;
}
errno_t yafw_connectOut(void *cookie, socket_t so, const struct sockaddr *to) {
	
	return KERN_SUCCESS;
}
errno_t yafw_bind(void *cookie, socket_t so, const struct sockaddr *to) {
	
	return KERN_SUCCESS;
}
errno_t yafw_setoption(void *cookie, socket_t so, sockopt_t opt) {
	
	return KERN_SUCCESS;
}
errno_t yafw_getoption(void *cookie, socket_t so, sockopt_t opt) {
	
	return KERN_SUCCESS;
}
errno_t yafw_listen(void *cookie, socket_t so) {
	
	return KERN_SUCCESS;
}
errno_t yafw_ioctl(void *cookie, socket_t so, unsigned long request, const char* argp) {
	
	return KERN_SUCCESS;
}
errno_t yafw_accept(void *cookie, socket_t so_listen, socket_t so, const struct sockaddr *local, const struct sockaddr *remote) {
	
	// Return EJUSTRETURN to prevent
	// return EJUSTRETURN;
	
	return KERN_SUCCESS;
}
