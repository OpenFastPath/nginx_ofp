
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ofp.h>

static ngx_int_t ngx_select_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static void ngx_select_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_select_add_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_select_del_event(ngx_event_t *ev, ngx_int_t event,
    ngx_uint_t flags);
static ngx_int_t ngx_select_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags);
/*static void ngx_select_repair_fd_sets(ngx_cycle_t *cycle);*/
static char *ngx_select_init_conf(ngx_cycle_t *cycle, void *conf);


static fd_set         master_read_fd_set;
static fd_set         master_write_fd_set;
static fd_set         work_read_fd_set;
static fd_set         work_write_fd_set;

static ngx_int_t      max_fd;
static ngx_uint_t     nevents;

static ngx_event_t  **event_index;


static ngx_str_t    select_name = ngx_string("select");

ngx_event_module_t  ngx_select_module_ctx = {
    &select_name,
    NULL,                                  /* create configuration */
    ngx_select_init_conf,                  /* init configuration */

    {
        ngx_select_add_event,              /* add an event */
        ngx_select_del_event,              /* delete an event */
        ngx_select_add_event,              /* enable an event */
        ngx_select_del_event,              /* disable an event */
        NULL,                              /* add an connection */
        NULL,                              /* delete an connection */
        NULL,                              /* trigger a notify */
        ngx_select_process_events,         /* process the events */
        ngx_select_init,                   /* init the events */
        ngx_select_done                    /* done the events */
    }

};

ngx_module_t  ngx_select_module = {
    NGX_MODULE_V1,
    &ngx_select_module_ctx,                /* module context */
    NULL,                                  /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

#define OFP_NOTIFY  0
#define ODP_FD_BITS 30
#undef FD_SET
#define CHK_FD_BIT(fd)          (fd & (1 << ODP_FD_BITS))
#define CLR_FD_BIT(fd)          (fd & ~(1 << ODP_FD_BITS))
#define FD_SET(fd, fdsetp)      do { \
				if (CHK_FD_BIT(fd)) {  \
				   OFP_FD_SET (CLR_FD_BIT(fd) , (ofp_fd_set *)fdsetp) ; \
				} else { \
				   OFP_FD_SET (fd , (ofp_fd_set *)fdsetp) ; \
				} \
				} while (0)

#undef FD_ISSET
#define FD_ISSET(fd, fdsetp)    OFP_FD_ISSET(CLR_FD_BIT(fd), (ofp_fd_set *)fdsetp)

#undef FD_CLR
#define FD_CLR(fd, fdsetp)      OFP_FD_CLR (CLR_FD_BIT(fd), (ofp_fd_set *)fdsetp)
#if OFP_NOTIFY
static void sigev_notify(union ofp_sigval sv)
{
    struct ofp_sock_sigval *ss = sv.sival_ptr;
    if (!ss)
       return ;
    int s = ss->sockfd;
    int event = ss->event;
    odp_packet_t pkt = ss->pkt;
    ngx_uint_t         i = 0;
    ngx_queue_t       *queue = NULL;
    ngx_event_t       *ev;
    ngx_connection_t  *c;

    if (event == OFP_EVENT_ACCEPT)  {
        for (i = 0; i < nevents; i++) {
            ev = event_index[i];
            c  = ev->data;

            if (ev->accept) {
                ev->ready = 1;
                ev->handler(ev);
                OFP_DBG("%s: posted on ACCEPT EVENT", __func__);
                break;
            }
        }
    }

    if (event != OFP_EVENT_RECV) {
        goto end;
    }

    int r = odp_packet_len(pkt);

    if (r > 0) {
        for (i = 0; i < nevents; i++) {
            ev = event_index[i];
            c  = ev->data;
            if (s == CLR_FD_BIT(c->fd))  {
                queue = &ngx_posted_events;
                ngx_post_event(ev, queue);
                OFP_DBG("%s: posted on RECV EVENT", __func__);
                ev->ready = 1;
                break;
            }
        }
    } else if (r == 0) {
        odp_packet_free(pkt);
        ss->pkt = ODP_PACKET_INVALID;
    }

end:
    return;
}
#endif


static ngx_int_t
ngx_select_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_event_t  **index;

    if (event_index == NULL) {
        FD_ZERO(&master_read_fd_set);
        FD_ZERO(&master_write_fd_set);
        nevents = 0;
    }

    if (ngx_process >= NGX_PROCESS_WORKER
        || cycle->old_cycle == NULL
        || cycle->old_cycle->connection_n < cycle->connection_n)
    {
        index = ngx_alloc(sizeof(ngx_event_t *) * 2 * cycle->connection_n,
                          cycle->log);
        if (index == NULL) {
            return NGX_ERROR;
        }

        if (event_index) {
            ngx_memcpy(index, event_index, sizeof(ngx_event_t *) * nevents);
            ngx_free(event_index);
        }

        event_index = index;
    }

    ngx_io = ngx_os_io;

    ngx_event_actions = ngx_select_module_ctx.actions;

    ngx_event_flags = NGX_USE_LEVEL_EVENT;

    max_fd = -1;

#if OFP_NOTIFY
    ngx_uint_t        i;
    ngx_listening_t  *ls;
    struct ofp_sigevent sigev;
    struct ofp_sock_sigval socksig;
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        if ((ls[i].listen) && (CHK_FD_BIT(ls[i].fd))) {
            socksig.sockfd = CLR_FD_BIT(ls[i].fd);
            socksig.event = 0;
            socksig.pkt = ODP_PACKET_INVALID;
            sigev.ofp_sigev_notify = 1;
            sigev.ofp_sigev_notify_function = sigev_notify;
            sigev.ofp_sigev_value.sival_ptr = &socksig;
            ofp_socket_sigevent(&sigev);
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                            "Set ofp notity on fd : %d",
                                        socksig.sockfd);
        }
    }
#endif
    return NGX_OK;
}


static void
ngx_select_done(ngx_cycle_t *cycle)
{
    ngx_free(event_index);

    event_index = NULL;
}


static ngx_int_t
ngx_select_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "%s: select add event fd:%d ev:%i", __func__, c->fd, event);

    if (ev->index != NGX_INVALID_INDEX) {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "select event fd:%d ev:%i is already set", c->fd, event);
        return NGX_OK;
    }

    if ((event == NGX_READ_EVENT && ev->write)
        || (event == NGX_WRITE_EVENT && !ev->write))
    {
        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "invalid select %s event fd:%d ev:%i",
                      ev->write ? "write" : "read", c->fd, event);
        return NGX_ERROR;
    }


        ngx_log_debug(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                      "select %s event fd:%d  event:%d",
                      ev->write ? "write" : "read", c->fd, event);

#if !(OFP_NOTIFY)
    if (event == NGX_READ_EVENT) {
	if (CHK_FD_BIT(c->fd)) {
            FD_SET(c->fd, (ofp_fd_set *)&master_read_fd_set);
	}
    } else if (event == NGX_WRITE_EVENT) {
        FD_SET(c->fd, &master_write_fd_set);
    }
#endif

    if (max_fd != -1 && max_fd < c->fd) {
        max_fd = c->fd;
    }

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                      "%s: select event fd:%d  max_fd:%d",
                       __func__, c->fd, max_fd);
    ev->active = 1;

    event_index[nevents] = ev;
    ev->index = nevents;
    nevents++;

    return NGX_OK;
}


static ngx_int_t
ngx_select_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    ngx_event_t       *e;
    ngx_connection_t  *c;

    c = ev->data;

    ev->active = 0;

    if (ev->index == NGX_INVALID_INDEX) {
        return NGX_OK;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                   "select del event fd:%d ev:%i", c->fd, event);

#if !OFP_NOTIFY
    if (event == NGX_READ_EVENT) {
        FD_CLR(c->fd, &master_read_fd_set);

    } else if (event == NGX_WRITE_EVENT) {
        FD_CLR(c->fd, &master_write_fd_set);
    }
#endif

    if (max_fd == c->fd) {
        max_fd = -1;
    }

    if (ev->index < --nevents) {
        e = event_index[nevents];
        event_index[ev->index] = e;
        e->index = ev->index;
    }

    ev->index = NGX_INVALID_INDEX;

    return NGX_OK;
}


static ngx_int_t
ngx_select_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,
    ngx_uint_t flags)
{
	odp_event_t odp_ev;
	odp_packet_t pkt;
	odp_queue_t in_queue;
	odp_event_t events[OFP_EVT_RX_BURST_SIZE];
	int event_idx = 0;
	int event_cnt = 0;

	event_cnt = odp_schedule_multi(&in_queue, ODP_SCHED_NO_WAIT,
			 events, OFP_EVT_RX_BURST_SIZE);
	for (event_idx = 0; event_idx < event_cnt; event_idx++) {
		odp_ev = events[event_idx];

		if (odp_ev == ODP_EVENT_INVALID)
			continue;

		if (odp_event_type(odp_ev) == ODP_EVENT_TIMEOUT) {
			ofp_timer_handle(odp_ev);
			continue;
		}

		if (odp_event_type(odp_ev) == ODP_EVENT_PACKET) {
			pkt = odp_packet_from_event(odp_ev);
			ofp_packet_input(pkt, in_queue, ofp_eth_vlan_processing);
			continue;
		}

		OFP_ERR("Unexpected event type: %u", odp_event_type(odp_ev));
	}
#if OFP_NOTIFY
    return NGX_OK;
#endif
    int                ready, nready;
    ngx_err_t          err;
    ngx_uint_t         i, found;
    ngx_event_t       *ev;
    ngx_queue_t       *queue;
    struct timeval     tv, *tp;
    ngx_connection_t  *c;

    if (max_fd == -1) {
        for (i = 0; i < nevents; i++) {
            c = event_index[i]->data;
        ngx_log_debug(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "change max_fd: %i, c->fd : %d", max_fd, c->fd);
            if (max_fd < c->fd) {
                max_fd = c->fd;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "change max_fd: %i", max_fd);
    }

#if (NGX_DEBUG)
    if (cycle->log->log_level & NGX_LOG_DEBUG_ALL) {
        for (i = 0; i < nevents; i++) {
            ev = event_index[i];
            c = ev->data;
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "select event: fd:%d wr:%d", c->fd, ev->write);
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "max_fd: %i", max_fd);
    }
#endif

    if (timer == NGX_TIMER_INFINITE) {
        tp = NULL;

    } else {
        tv.tv_sec = (long) (timer / 1000);
        tv.tv_usec = (long) ((timer % 1000) * 1000);
        tp = &tv;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select timer: %M", timer);

    work_read_fd_set = master_read_fd_set;
    work_write_fd_set = master_write_fd_set;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select max_fd %d, tp %p ", max_fd, tp);
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   " master %p : work %p", (ofp_fd_set *)&master_read_fd_set,
		   (ofp_fd_set *)&work_read_fd_set);
    ready = select(max_fd + 1, &work_read_fd_set, &work_write_fd_set, NULL, tp);

    err = (ready == -1) ? ngx_errno : 0;

    if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) {
        ngx_time_update();
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "select ready %d", ready);

    if (err) {
        ngx_uint_t  level;

        if (err == NGX_EINTR) {

            if (ngx_event_timer_alarm) {
                ngx_event_timer_alarm = 0;
                return NGX_OK;
            }

            level = NGX_LOG_INFO;

        } else {
            level = NGX_LOG_ALERT;
        }

        ngx_log_error(level, cycle->log, err, "select() failed");

        if (err == NGX_EBADF) {
            /*ngx_select_repair_fd_sets(cycle);*/
        }

        return NGX_ERROR;
    }

    if (ready == 0) {
return NGX_OK;
        if (timer != NGX_TIMER_INFINITE) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "select() returned no events without timeout");
        return NGX_ERROR;
    }

    nready = 0;

    for (i = 0; i < nevents; i++) {
        ev = event_index[i];
        c = ev->data;
        found = 0;

        if (ev->write) {
            if (FD_ISSET(c->fd, &work_write_fd_set)) {
                found = 1;
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select write %d", c->fd);
            }

        } else {
            if (FD_ISSET(c->fd, &work_read_fd_set)) {
                found = 1;
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                               "select read %d", c->fd);
            }
        }

        if (found) {
            ev->ready = 1;

            queue = ev->accept ? &ngx_posted_accept_events
                               : &ngx_posted_events;

            ngx_post_event(ev, queue);

            nready++;
        }
    }

    if (ready != nready) {
        /*ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "select ready != events: %d:%d", ready, nready);

        ngx_select_repair_fd_sets(cycle);*/
    }

    return NGX_OK;
}

/*
static void
ngx_select_repair_fd_sets(ngx_cycle_t *cycle)
{
    int           n;
    socklen_t     len;
    ngx_err_t     err;
    ngx_socket_t  s;

    for (s = 0; s <= max_fd; s++) {

        if (FD_ISSET(s, &master_read_fd_set) == 0) {
            continue;
        }

        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, &n, &len) == -1) {
            err = ngx_socket_errno;

            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          "invalid descriptor #%d in read fd_set", s);

            FD_CLR(s, &master_read_fd_set);
        }
    }

    for (s = 0; s <= max_fd; s++) {

        if (FD_ISSET(s, &master_write_fd_set) == 0) {
            continue;
        }

        len = sizeof(int);

        if (getsockopt(s, SOL_SOCKET, SO_TYPE, &n, &len) == -1) {
            err = ngx_socket_errno;

            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          "invalid descriptor #%d in write fd_set", s);

            FD_CLR(s, &master_write_fd_set);
        }
    }

    max_fd = -1;
}
*/

static char *
ngx_select_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_event_conf_t  *ecf;

    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    if (ecf->use != ngx_select_module.ctx_index) {
        return NGX_CONF_OK;
    }

    /* disable warning: the default FD_SETSIZE is 1024U in FreeBSD 5.x */

    if (cycle->connection_n > FD_SETSIZE) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "the maximum number of files "
                      "supported by select() is %ud", FD_SETSIZE);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
