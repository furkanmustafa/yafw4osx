//
//  filters.h
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

#ifndef yafw_filters_h
#define yafw_filters_h

void yafw_unregistered(sflt_handle handle);										/* sf_unregistered_func */
errno_t yafw_attach(void **cookie, socket_t so);								/* sf_attach_func */
void yafw_detach(void *cookie, socket_t so);									/* sf_detach_func */
void yafw_notify(void *cookie, socket_t so, sflt_event_t event, void *param);	/* sf_notify_func */
int yafw_getpeername(void *cookie, socket_t so, struct sockaddr **sa);			/* sf_getpeername_func */
int yafw_getsockname(void *cookie, socket_t so, struct sockaddr **sa);			/* sf_getsockname_func */
errno_t yafw_dataIn(void *cookie, socket_t so, const struct sockaddr *from, mbuf_t *data, mbuf_t *control,
						sflt_data_flag_t flags);									/* sf_data_in_func */
errno_t yafw_dataOut(void *cookie, socket_t so, const struct sockaddr *to, mbuf_t *data, mbuf_t *control,
						 sflt_data_flag_t flags);									/* sf_data_out_func */
errno_t yafw_connectIn(void *cookie, socket_t so, const struct sockaddr *from);	/* sf_connect_in_func */
errno_t yafw_connectOut(void *cookie, socket_t so, const struct sockaddr *to);	/* sf_connect_out_func */
errno_t yafw_bind(void *cookie, socket_t so, const struct sockaddr *to);		/* sf_bind_func */
errno_t yafw_setoption(void *cookie, socket_t so, sockopt_t opt);				/* sf_setoption_func */
errno_t yafw_getoption(void *cookie, socket_t so, sockopt_t opt);				/* sf_getoption_func */
errno_t yafw_listen(void *cookie, socket_t so);									/* sf_listen_func */
errno_t yafw_ioctl(void *cookie, socket_t so, unsigned long request,
					   const char* argp);											/* sf_ioctl_func */
errno_t yafw_accept(void *cookie, socket_t so_listen, socket_t so, const struct sockaddr *local,
						const struct sockaddr *remote);								/* sf_filter_ext */

#endif
