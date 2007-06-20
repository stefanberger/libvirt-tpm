/*
 * qemu_internal.c: A backend for managing QEMU machines
 *
 * Copyright (C) 2006-2007 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifdef WITH_QEMU
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/uri.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <limits.h>
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#ifndef _PATH_DEVNULL
#define	_PATH_DEVNULL	"/dev/null"
#endif


#include "internal.h"
#include "qemu_internal.h"
#include "xml.h"
#include "protocol.h"
#include "remote_protocol.h"

/**
 * qemuPrivatePtr:
 *
 * Per-connection private data.
 */
struct _qemuPrivate {
    int qemud_fd;               /* Connection to libvirt qemu daemon. */
    unsigned int qemud_serial_out;
    unsigned int qemud_serial_in;
};
struct _qemuNetworkPrivate {
    int qemud_fd;
    int shared;
};
typedef struct _qemuPrivate *qemuPrivatePtr;
typedef struct _qemuNetworkPrivate *qemuNetworkPrivatePtr;

static void
qemuError(virConnectPtr con,
           virDomainPtr dom,
           virErrorNumber error,
           const char *info)
{
    const char *errmsg;

    if (error == VIR_ERR_OK)
        return;

    errmsg = __virErrorMsg(error, info);
    __virRaiseError(con, dom, NULL, VIR_FROM_QEMU, error, VIR_ERR_ERROR,
                    errmsg, info, NULL, 0, 0, errmsg, info, 0);
}


/**
 * qemuFindServerPath:
 *
 * Tries to find the path to the qemu binary.
 * 
 * Returns path on success or NULL in case of error.
 */
static const char *
qemuFindServerPath(void)
{
    static const char *serverPaths[] = {
        SBINDIR "/libvirt_qemud",
        SBINDIR "/libvirt_qemud_dbg",
        NULL
    };
    int i;
    const char *debugQemu = getenv("LIBVIRT_QEMU_SERVER");

    if (debugQemu)
        return(debugQemu);

    for (i = 0; serverPaths[i]; i++) {
        if (access(serverPaths[i], X_OK | R_OK) == 0) {
            return serverPaths[i];
        }
    }
    return NULL;
}


/**
 * qemuForkServer:
 *
 * Forks and try to launch the qemu server
 *
 * Returns 0 in case of success or -1 in case of detected error.
 */
static int
qemuForkServer(void)
{
    const char *proxyPath = qemuFindServerPath();
    int ret, pid, status;

    if (!proxyPath) {
        qemuError (NULL, NULL, VIR_ERR_INVALID_ARG, "no proxyPath");
        return(-1);
    }

    /* Become a daemon */
    pid = fork();
    if (pid == 0) {
        int stdinfd = -1;
        int stdoutfd = -1;
        int i, open_max;
        if ((stdinfd = open(_PATH_DEVNULL, O_RDONLY)) < 0)
            goto cleanup;
        if ((stdoutfd = open(_PATH_DEVNULL, O_WRONLY)) < 0)
            goto cleanup;
        if (dup2(stdinfd, STDIN_FILENO) != STDIN_FILENO)
            goto cleanup;
        if (dup2(stdoutfd, STDOUT_FILENO) != STDOUT_FILENO)
            goto cleanup;
        if (dup2(stdoutfd, STDERR_FILENO) != STDERR_FILENO)
            goto cleanup;
        if (close(stdinfd) < 0)
            goto cleanup;
        stdinfd = -1;
        if (close(stdoutfd) < 0)
            goto cleanup;
        stdoutfd = -1;

        open_max = sysconf (_SC_OPEN_MAX);
        for (i = 0; i < open_max; i++)
            if (i != STDIN_FILENO &&
                i != STDOUT_FILENO &&
                i != STDERR_FILENO)
                close(i);

        setsid();
        if (fork() == 0) {
            /* Run daemon in auto-shutdown mode, so it goes away when
               no longer needed by an active guest, or client */
            execl(proxyPath, proxyPath, "--timeout", "30", NULL);
            fprintf(stderr, "failed to exec %s\n", proxyPath);
        }
        /*
         * calling exit() generate troubles for termination handlers
         */
        _exit(0);

    cleanup:
        if (stdoutfd != -1)
            close(stdoutfd);
        if (stdinfd != -1)
            close(stdinfd);
        _exit(-1);
    }

    /*
     * do a waitpid on the intermediate process to avoid zombies.
     */
 retry_wait:
    ret = waitpid(pid, &status, 0);
    if (ret < 0) {
        if (errno == EINTR)
            goto retry_wait;
    }

    return (0);
}

/**
 * qemuOpenClientUNIX:
 * @path: the fileame for the socket
 *
 * try to connect to the socket open by qemu
 *
 * Returns the associated file descriptor or -1 in case of failure
 */
static int
qemuOpenClientUNIX(virConnectPtr conn ATTRIBUTE_UNUSED,
                   const char *path, int autostart) {
    int fd;
    struct sockaddr_un addr;
    int trials = 0;

 retry:
    fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        qemuError (NULL, NULL, VIR_ERR_SYSTEM_ERROR, "socket");
        return VIR_DRV_OPEN_ERROR;
    }

    /*
     * Abstract socket do not hit the filesystem, way more secure and
     * garanteed to be atomic
     */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    if (addr.sun_path[0] == '@')
        addr.sun_path[0] = '\0';

    /*
     * now bind the socket to that address and listen on it
     */
    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        if (autostart && trials < 3) {
            if (qemuForkServer() < 0)
                return(-1);
            trials++;
            usleep(5000 * trials * trials);
            goto retry;
        }
        __virRaiseError (NULL, NULL, NULL,
                         VIR_FROM_QEMU, VIR_ERR_SYSTEM_ERROR, VIR_ERR_ERROR,
                         "connect", NULL, NULL, errno, 0,
                         "connect: %s: %s", path, strerror (errno));
        return VIR_DRV_OPEN_ERROR;
    }

    return fd;
}

static int
qemudXdrWrite(int qemud_fd, char *buffer, int length)
{
    int done = 0;

    while (done < length) {
        int ret = write(qemud_fd, buffer+done, length-done);
        if (ret <= 0)
            return -1;
        done += ret;
    }
    return done;
}

static int
qemudXdrRead(int qemud_fd, char *buffer, int length)
{
    int done = 0;

    while (done < length) {
        int ret = read(qemud_fd, buffer+done, length-done);
        if (ret <= 0)
            return -1;
        done += ret;
    }
    return done;
}

/* Takes a single request packet, does a blocking send on it.
 * then blocks until the complete reply has come back, or
 * connection closes.
 */
static int qemuProcessRequest(virConnectPtr conn,
                              int qemud_fd,
                              virDomainPtr dom,
                              qemud_packet_client *req,
                              qemud_packet_server *reply) {
    XDR x;
    char buffer[REMOTE_MESSAGE_MAX];
    qemud_packet_header h;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req->serial = ++priv->qemud_serial_out;

    /* Create the buffer. */
    xdrmem_create(&x, buffer, sizeof buffer, XDR_ENCODE);

    /* Encode a dummy header first - we'll come back for the real header. */
    if (!xdr_qemud_packet_header (&x, &h)) {
        fprintf (stderr, "Encoding dummy header\n");
        return -1;
    }

    /* Client payload. */
    if (!xdr_qemud_packet_client(&x, req)) {
        fprintf(stderr, "Cannot encode client payload\n");
        return -1;
    }

    /* Get the total length. */
    h.length = xdr_getpos (&x);
    h.prog = QEMUD_PROGRAM;

    /* Encode the real header at the start of the message. */
    if (xdr_setpos (&x, 0) == 0) {
        fprintf (stderr, "xdr_setpos\n");
        return -1;
    }

    if (!xdr_qemud_packet_header(&x, &h)) {
        fprintf(stderr, "Cannot encode client header\n");
        return -1;
    }
    xdr_destroy (&x);

    if (qemudXdrWrite(qemud_fd, buffer, h.length) < 0) {
        fprintf(stderr, "Cannot write client packet\n");
        return -1;
    }

    /* Read the reply header. */
    if (qemudXdrRead(qemud_fd, buffer, QEMUD_PKT_HEADER_XDR_LEN) < 0) {
        fprintf(stderr, "Cannot read server header\n");
        return -1;
    }

    xdrmem_create(&x, buffer, QEMUD_PKT_HEADER_XDR_LEN, XDR_DECODE);

    if (!xdr_qemud_packet_header(&x, &h)) {
        fprintf(stderr, "Cannot decode server header\n");
        return -1;
    }

    if (h.prog != QEMUD_PROGRAM) {
        fprintf(stderr, "Server header magic %d does not match %d\n",
                h.prog, QEMUD_PROGRAM);
        return -1;
    }

    /* Adjust h.length to the number of bytes remaining to be read. */
    h.length -= 8;

    /* NB: h.length is unsigned. */
    if (h.length > REMOTE_MESSAGE_MAX) {
        fprintf(stderr, "Server payload length %d is longer than max %d\n",
                h.length, REMOTE_MESSAGE_MAX);
        return -1;
    }

    /* Read and parse the remainder of the message. */
    if (qemudXdrRead(qemud_fd, buffer, h.length) < 0) {
        fprintf(stderr, "Cannot read server payload\n");
        return -1;
    }

    xdrmem_create(&x, buffer, h.length, XDR_DECODE);

    if (!xdr_qemud_packet_server(&x, reply)) {
        fprintf(stderr, "Cannot decode server payload\n");
        return -1;
    }

    if (reply->serial != ++priv->qemud_serial_in) {
        fprintf(stderr, "Server serial %d did not match expected %d\n",
                reply->serial, priv->qemud_serial_in);
        return -1;
    }
    if (reply->inReplyTo != req->serial) {
        fprintf(stderr, "Server inReplyTo %d did not match expected %d\n",
                reply->inReplyTo, priv->qemud_serial_out);
        return -1;
    }

    if (reply->data.type == QEMUD_SERVER_PKT_FAILURE) {
        /* Paranoia in case remote side didn't terminate it */
        if (reply->data.qemud_packet_server_data_u.failureReply.message[0])
            reply->data.qemud_packet_server_data_u.failureReply.message[QEMUD_MAX_ERROR_LEN-1] = '\0';

        qemuError(conn,
                  dom,
                  reply->data.qemud_packet_server_data_u.failureReply.code,
                  reply->data.qemud_packet_server_data_u.failureReply.message[0] ?
                  reply->data.qemud_packet_server_data_u.failureReply.message : NULL);
        return -1;
    }

    /* XXX validate type is what we expect */

    return 0;
}


/*
 * Open a connection to the libvirt QEMU daemon
 */
static int qemuOpenConnection(virConnectPtr conn, xmlURIPtr uri, int readonly) {
    char path[PATH_MAX];
    int autostart = 0;

    if (uri->server != NULL) {
        qemuError (NULL, NULL, VIR_ERR_INTERNAL_ERROR, __FUNCTION__);
        return VIR_DRV_OPEN_ERROR;
    }

    if (strcmp(uri->path, "/system") == 0) {
        if (readonly) {
            if (snprintf(path, sizeof(path), "%s/run/libvirt/qemud-sock-ro", LOCAL_STATE_DIR) >= (int)sizeof(path)) {
                qemuError (NULL, NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
                return VIR_DRV_OPEN_ERROR;
            }
        } else {
            if (snprintf(path, sizeof(path), "%s/run/libvirt/qemud-sock", LOCAL_STATE_DIR) >= (int)sizeof(path)) {
                qemuError (NULL, NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
                return VIR_DRV_OPEN_ERROR;
            }
        }
    } else if (strcmp(uri->path, "/session") == 0) {
        struct passwd *pw;
        int uid;

        if ((uid = geteuid()) < 0) {
            qemuError (NULL, NULL, VIR_ERR_SYSTEM_ERROR, "geteuid");
            return VIR_DRV_OPEN_ERROR;
        }

        if (!(pw = getpwuid(uid))) {
            qemuError (NULL, NULL, VIR_ERR_SYSTEM_ERROR, "getpwuid");
            return VIR_DRV_OPEN_ERROR;
        }

        if (snprintf(path, sizeof(path), "@%s/.libvirt/qemud-sock", pw->pw_dir) == sizeof(path)) {
            return VIR_DRV_OPEN_ERROR;
        }
        autostart = 1;
    } else {
        qemuError (NULL, NULL, VIR_ERR_INVALID_ARG, "path should be /system or /session - for example, qemu:///session");
        return VIR_DRV_OPEN_ERROR;
    }
    return qemuOpenClientUNIX(conn, path, autostart);
}


/*
 * Open a connection to the QEMU manager
 */
static int qemuOpen(virConnectPtr conn,
                    const char *name,
                    int flags){
    xmlURIPtr uri;
    qemuPrivatePtr priv;
    int ret;

    if (!name) {
        return VIR_DRV_OPEN_DECLINED;
    }

    uri = xmlParseURI(name);
    if (uri == NULL) {
        return VIR_DRV_OPEN_DECLINED;
    }

    if (!uri->scheme ||
        strcmp(uri->scheme, "qemu") ||
        uri->server || /* remote driver should handle these */
        !uri->path) {
        xmlFreeURI(uri);
        return VIR_DRV_OPEN_DECLINED;
    }

    /* Create per-connection private data. */
    priv = conn->privateData = calloc (1, sizeof *priv);
    if (!priv) {
        qemuError (NULL, NULL, VIR_ERR_NO_MEMORY, __FUNCTION__);
        return VIR_DRV_OPEN_ERROR;
    }

    ret = qemuOpenConnection(conn, uri, flags & VIR_DRV_OPEN_RO ? 1 : 0);
    xmlFreeURI(uri);

    if (ret < 0) {
        free (priv);
        conn->privateData = NULL;
        return VIR_DRV_OPEN_ERROR;
    }

    priv->qemud_fd = ret;

    return VIR_DRV_OPEN_SUCCESS;
}


static int
qemuClose (virConnectPtr conn)
{
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    if (priv->qemud_fd != -1) {
        close (priv->qemud_fd);
        priv->qemud_fd = -1;
    }

    free (priv);
    conn->privateData = NULL;

    return 0;
}


static int qemuGetVersion(virConnectPtr conn,
                          unsigned long *hvVer) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_GET_VERSION;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    *hvVer = reply.data.qemud_packet_server_data_u.getVersionReply.versionNum;
    return 0;
}


static int qemuNodeGetInfo(virConnectPtr conn,
                           virNodeInfoPtr info) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_GET_NODEINFO;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    info->cores = reply.data.qemud_packet_server_data_u.getNodeInfoReply.cores;
    info->threads = reply.data.qemud_packet_server_data_u.getNodeInfoReply.threads;
    info->sockets = reply.data.qemud_packet_server_data_u.getNodeInfoReply.sockets;
    info->nodes = reply.data.qemud_packet_server_data_u.getNodeInfoReply.nodes;
    strncpy(info->model, reply.data.qemud_packet_server_data_u.getNodeInfoReply.model, sizeof(info->model));
    info->mhz = reply.data.qemud_packet_server_data_u.getNodeInfoReply.mhz;
    info->cpus = reply.data.qemud_packet_server_data_u.getNodeInfoReply.cpus;
    info->memory = reply.data.qemud_packet_server_data_u.getNodeInfoReply.memory;
    return 0;
}


static char *
qemuGetCapabilities (virConnectPtr conn)
{
    qemud_packet_client req;
    qemud_packet_server reply;
    char *xml;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    /* Punt the request across to the daemon, because the daemon
     * has tables describing available architectures.
     */
    req.data.type = QEMUD_CLIENT_PKT_GET_CAPABILITIES;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.qemud_packet_server_data_u.getCapabilitiesReply.xml[QEMUD_MAX_XML_LEN-1] = '\0';

    xml = strdup (reply.data.qemud_packet_server_data_u.getCapabilitiesReply.xml);
    if (!xml) {
        qemuError (conn, NULL, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }

    return xml;
}

static int qemuNumOfDomains(virConnectPtr conn) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_NUM_DOMAINS;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return reply.data.qemud_packet_server_data_u.numDomainsReply.numDomains;
}


static int qemuListDomains(virConnectPtr conn,
                           int *ids,
                           int maxids) {
    qemud_packet_client req;
    qemud_packet_server reply;
    int i, nDomains;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_LIST_DOMAINS;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    nDomains = reply.data.qemud_packet_server_data_u.listDomainsReply.numDomains;
    if (nDomains > maxids)
        nDomains = maxids;

    for (i = 0 ; i < nDomains ; i++) {
        ids[i] = reply.data.qemud_packet_server_data_u.listDomainsReply.domains[i];
    }

    return nDomains;
}


static virDomainPtr
qemuDomainCreateLinux(virConnectPtr conn, const char *xmlDesc,
                       unsigned int flags ATTRIBUTE_UNUSED) {
    qemud_packet_client req;
    qemud_packet_server reply;
    virDomainPtr dom;
    int len = strlen(xmlDesc);
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    if (len > (QEMUD_MAX_XML_LEN-1)) {
        return NULL;
    }

    req.data.type = QEMUD_CLIENT_PKT_DOMAIN_CREATE;
    strcpy(req.data.qemud_packet_client_data_u.domainCreateRequest.xml, xmlDesc);
    req.data.qemud_packet_client_data_u.domainCreateRequest.xml[QEMUD_MAX_XML_LEN-1] = '\0';

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.qemud_packet_server_data_u.domainCreateReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(dom = virGetDomain(conn,
                             reply.data.qemud_packet_server_data_u.domainCreateReply.name,
                             reply.data.qemud_packet_server_data_u.domainCreateReply.uuid)))
        return NULL;

    dom->id = reply.data.qemud_packet_server_data_u.domainCreateReply.id;
    return dom;
}


static virDomainPtr qemuLookupDomainByID(virConnectPtr conn,
                                         int id) {
    qemud_packet_client req;
    qemud_packet_server reply;
    virDomainPtr dom;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_DOMAIN_LOOKUP_BY_ID;
    req.data.qemud_packet_client_data_u.domainLookupByIDRequest.id = id;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.qemud_packet_server_data_u.domainLookupByIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(dom = virGetDomain(conn,
                             reply.data.qemud_packet_server_data_u.domainLookupByIDReply.name,
                             reply.data.qemud_packet_server_data_u.domainLookupByIDReply.uuid)))
        return NULL;

    dom->id = id;
    return dom;
}


static virDomainPtr qemuLookupDomainByUUID(virConnectPtr conn,
                                           const unsigned char *uuid) {
    qemud_packet_client req;
    qemud_packet_server reply;
    virDomainPtr dom;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_DOMAIN_LOOKUP_BY_UUID;
    memmove(req.data.qemud_packet_client_data_u.domainLookupByUUIDRequest.uuid, uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.qemud_packet_server_data_u.domainLookupByUUIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(dom = virGetDomain(conn,
                             reply.data.qemud_packet_server_data_u.domainLookupByUUIDReply.name,
                             uuid)))
        return NULL;

    dom->id = reply.data.qemud_packet_server_data_u.domainLookupByUUIDReply.id;
    return dom;
}


static virDomainPtr qemuLookupDomainByName(virConnectPtr conn,
                                           const char *name) {
    qemud_packet_client req;
    qemud_packet_server reply;
    virDomainPtr dom;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    if (strlen(name) > (QEMUD_MAX_NAME_LEN-1))
        return NULL;

    req.data.type = QEMUD_CLIENT_PKT_DOMAIN_LOOKUP_BY_NAME;
    strcpy(req.data.qemud_packet_client_data_u.domainLookupByNameRequest.name, name);

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    if (!(dom = virGetDomain(conn,
                             name,
                             reply.data.qemud_packet_server_data_u.domainLookupByNameReply.uuid)))
        return NULL;

    dom->id = reply.data.qemud_packet_server_data_u.domainLookupByNameReply.id;
    return dom;
}

static int qemuDestroyDomain(virDomainPtr domain) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) domain->conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_DOMAIN_DESTROY;
    req.data.qemud_packet_client_data_u.domainDestroyRequest.id = domain->id;

    if (qemuProcessRequest(domain->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static char *qemuDomainGetOSType(virDomainPtr domain ATTRIBUTE_UNUSED) {
    char *type = strdup("hvm");

    if (!type) {
        qemuError (domain->conn, domain, VIR_ERR_NO_MEMORY, __FUNCTION__);
        return NULL;
    }

    return type;
}

static int qemuShutdownDomain(virDomainPtr domain) {
    return qemuDestroyDomain(domain);
}

static int qemuResumeDomain(virDomainPtr domain) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) domain->conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_DOMAIN_RESUME;
    req.data.qemud_packet_client_data_u.domainResumeRequest.id = domain->id;

    if (qemuProcessRequest(domain->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static int qemuPauseDomain(virDomainPtr domain) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) domain->conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_DOMAIN_SUSPEND;
    req.data.qemud_packet_client_data_u.domainSuspendRequest.id = domain->id;

    if (qemuProcessRequest(domain->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static int qemuGetDomainInfo(virDomainPtr domain,
                             virDomainInfoPtr info) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) domain->conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_DOMAIN_GET_INFO;
    memmove(req.data.qemud_packet_client_data_u.domainGetInfoRequest.uuid, domain->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(domain->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    memset(info, 0, sizeof(virDomainInfo));
    switch (reply.data.qemud_packet_server_data_u.domainGetInfoReply.runstate) {
    case QEMUD_STATE_RUNNING:
        info->state = VIR_DOMAIN_RUNNING;
        break;

    case QEMUD_STATE_PAUSED:
        info->state = VIR_DOMAIN_PAUSED;
        break;

    case QEMUD_STATE_STOPPED:
        info->state = VIR_DOMAIN_SHUTOFF;
        break;

    default:
        return -1;
    }
    info->maxMem = reply.data.qemud_packet_server_data_u.domainGetInfoReply.maxmem;
    info->memory = reply.data.qemud_packet_server_data_u.domainGetInfoReply.memory;
    info->nrVirtCpu = reply.data.qemud_packet_server_data_u.domainGetInfoReply.nrVirtCpu;
    info->cpuTime = reply.data.qemud_packet_server_data_u.domainGetInfoReply.cpuTime;

    return 0;
}

static char *qemuDomainDumpXML(virDomainPtr domain, int flags ATTRIBUTE_UNUSED) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) domain->conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_DUMP_XML;
    memmove(req.data.qemud_packet_client_data_u.domainDumpXMLRequest.uuid, domain->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(domain->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.qemud_packet_server_data_u.domainDumpXMLReply.xml[QEMUD_MAX_XML_LEN-1] = '\0';

    return strdup(reply.data.qemud_packet_server_data_u.domainDumpXMLReply.xml);
}

static int qemuSaveDomain(virDomainPtr domain ATTRIBUTE_UNUSED, const char *file ATTRIBUTE_UNUSED) {
    return -1;
}

static int qemuRestoreDomain(virConnectPtr conn ATTRIBUTE_UNUSED, const char *file ATTRIBUTE_UNUSED) {
    return -1;
}


static int qemuNumOfDefinedDomains(virConnectPtr conn) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_NUM_DEFINED_DOMAINS;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return reply.data.qemud_packet_server_data_u.numDefinedDomainsReply.numDomains;
}

static int qemuListDefinedDomains(virConnectPtr conn,
                                  char **const names,
                                  int maxnames){
    qemud_packet_client req;
    qemud_packet_server reply;
    int i, nDomains;
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_LIST_DEFINED_DOMAINS;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    nDomains = reply.data.qemud_packet_server_data_u.listDefinedDomainsReply.numDomains;
    if (nDomains > maxnames)
        nDomains = maxnames;

    for (i = 0 ; i < nDomains ; i++) {
        reply.data.qemud_packet_server_data_u.listDefinedDomainsReply.domains[((i+1)*QEMUD_MAX_NAME_LEN)-1] = '\0';
        names[i] = strdup(&reply.data.qemud_packet_server_data_u.listDefinedDomainsReply.domains[i*QEMUD_MAX_NAME_LEN]);
    }

    return nDomains;
}

static int qemuDomainCreate(virDomainPtr dom) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) dom->conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_DOMAIN_START;
    memcpy(req.data.qemud_packet_client_data_u.domainStartRequest.uuid, dom->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(dom->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    dom->id = reply.data.qemud_packet_server_data_u.domainStartReply.id;

    return 0;
}

static virDomainPtr qemuDomainDefineXML(virConnectPtr conn, const char *xml) {
    qemud_packet_client req;
    qemud_packet_server reply;
    virDomainPtr dom;
    int len = strlen(xml);
    qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;

    if (len > (QEMUD_MAX_XML_LEN-1)) {
        return NULL;
    }

    req.data.type = QEMUD_CLIENT_PKT_DOMAIN_DEFINE;
    strcpy(req.data.qemud_packet_client_data_u.domainDefineRequest.xml, xml);
    req.data.qemud_packet_client_data_u.domainDefineRequest.xml[QEMUD_MAX_XML_LEN-1] = '\0';

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.qemud_packet_server_data_u.domainDefineReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(dom = virGetDomain(conn,
                             reply.data.qemud_packet_server_data_u.domainDefineReply.name,
                             reply.data.qemud_packet_server_data_u.domainDefineReply.uuid)))
        return NULL;

    dom->id = -1;
    return dom;
}

static int qemuUndefine(virDomainPtr dom) {
    qemud_packet_client req;
    qemud_packet_server reply;
    int ret = 0;
    qemuPrivatePtr priv = (qemuPrivatePtr) dom->conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_DOMAIN_UNDEFINE;
    memcpy(req.data.qemud_packet_client_data_u.domainUndefineRequest.uuid, dom->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(dom->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        ret = -1;
        goto cleanup;
    }

 cleanup:
    if (virFreeDomain(dom->conn, dom) < 0)
        ret = -1;

    return ret;
}

static int qemuDomainGetAutostart(virDomainPtr dom,
                                  int *autostart) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) dom->conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_DOMAIN_GET_AUTOSTART;
    memmove(req.data.qemud_packet_client_data_u.domainGetAutostartRequest.uuid, dom->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(dom->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    *autostart = reply.data.qemud_packet_server_data_u.domainGetAutostartReply.autostart;

    return 0;
}

static int qemuDomainSetAutostart(virDomainPtr dom,
                                  int autostart) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuPrivatePtr priv = (qemuPrivatePtr) dom->conn->privateData;

    req.data.type = QEMUD_CLIENT_PKT_DOMAIN_SET_AUTOSTART;
    req.data.qemud_packet_client_data_u.domainSetAutostartRequest.autostart = (
autostart != 0);
    memmove(req.data.qemud_packet_client_data_u.domainSetAutostartRequest.uuid,
 dom->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(dom->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static int qemuNetworkOpen(virConnectPtr conn,
                           const char *name ATTRIBUTE_UNUSED,
                           int flags) {
    qemuNetworkPrivatePtr netpriv = NULL;

    if (!(netpriv = malloc(sizeof(struct _qemuNetworkPrivate)))) {
        qemuError (conn, NULL, VIR_ERR_NO_MEMORY, __FUNCTION__);
        return VIR_DRV_OPEN_ERROR;
    }

    if (!strcmp(conn->driver->name, "QEMU")) {
        /* QEMU driver is active - just re-use existing connection */
        qemuPrivatePtr priv = (qemuPrivatePtr) conn->privateData;
        netpriv->qemud_fd = priv->qemud_fd;
        netpriv->shared = 1;
        conn->networkPrivateData = netpriv;
        return VIR_DRV_OPEN_SUCCESS;
    } else {
        /* Non-QEMU driver is active - open a new connection */
        const char *drvname = geteuid() == 0 ? "qemu:///system" : "qemu:///session";
        xmlURIPtr uri = xmlParseURI(drvname);
        int ret = qemuOpenConnection(conn, uri, flags & VIR_DRV_OPEN_RO ? 1 : 0);
        xmlFreeURI(uri);

        if (ret < 0) {
            free(netpriv);
            return ret;
        } else {
            netpriv->qemud_fd = ret;
            netpriv->shared = 0;
            conn->networkPrivateData = netpriv;
            return VIR_DRV_OPEN_SUCCESS;
        }
    }
}

static int
qemuNetworkClose (virConnectPtr conn)
{
    qemuNetworkPrivatePtr netpriv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    if (!netpriv->shared)
        close(netpriv->qemud_fd);
    free(netpriv);
    conn->networkPrivateData = NULL;

    return 0;
}

static int qemuNumOfNetworks(virConnectPtr conn) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    req.data.type = QEMUD_CLIENT_PKT_NUM_NETWORKS;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return reply.data.qemud_packet_server_data_u.numNetworksReply.numNetworks;
}

static int qemuListNetworks(virConnectPtr conn,
                            char **const names,
                            int maxnames) {
    qemud_packet_client req;
    qemud_packet_server reply;
    int i, nNetworks;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    req.data.type = QEMUD_CLIENT_PKT_LIST_NETWORKS;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    nNetworks = reply.data.qemud_packet_server_data_u.listNetworksReply.numNetworks;
    if (nNetworks > maxnames)
        return -1;

    for (i = 0 ; i < nNetworks ; i++) {
        reply.data.qemud_packet_server_data_u.listNetworksReply.networks[((i+1)*QEMUD_MAX_NAME_LEN)-1] = '\0';
        names[i] = strdup(&reply.data.qemud_packet_server_data_u.listNetworksReply.networks[i*QEMUD_MAX_NAME_LEN]);
    }

    return nNetworks;
}

static int qemuNumOfDefinedNetworks(virConnectPtr conn) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    req.data.type = QEMUD_CLIENT_PKT_NUM_DEFINED_NETWORKS;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return reply.data.qemud_packet_server_data_u.numDefinedNetworksReply.numNetworks;
}

static int qemuListDefinedNetworks(virConnectPtr conn,
                                   char **const names,
                                   int maxnames) {
    qemud_packet_client req;
    qemud_packet_server reply;
    int i, nNetworks;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    req.data.type = QEMUD_CLIENT_PKT_LIST_DEFINED_NETWORKS;

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    nNetworks = reply.data.qemud_packet_server_data_u.listDefinedNetworksReply.numNetworks;
    if (nNetworks > maxnames)
        return -1;

    for (i = 0 ; i < nNetworks ; i++) {
        reply.data.qemud_packet_server_data_u.listDefinedNetworksReply.networks[((i+1)*QEMUD_MAX_NAME_LEN)-1] = '\0';
        names[i] = strdup(&reply.data.qemud_packet_server_data_u.listDefinedNetworksReply.networks[i*QEMUD_MAX_NAME_LEN]);
    }

    return nNetworks;
}

static virNetworkPtr qemuNetworkLookupByUUID(virConnectPtr conn,
                                             const unsigned char *uuid) {
    qemud_packet_client req;
    qemud_packet_server reply;
    virNetworkPtr network;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    req.data.type = QEMUD_CLIENT_PKT_NETWORK_LOOKUP_BY_UUID;
    memmove(req.data.qemud_packet_client_data_u.networkLookupByUUIDRequest.uuid, uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.qemud_packet_server_data_u.networkLookupByUUIDReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(network = virGetNetwork(conn,
                                  reply.data.qemud_packet_server_data_u.networkLookupByUUIDReply.name,
                                  uuid)))
        return NULL;

    return network;
}

static virNetworkPtr qemuNetworkLookupByName(virConnectPtr conn,
                                             const char *name) {
    qemud_packet_client req;
    qemud_packet_server reply;
    virNetworkPtr network;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    if (strlen(name) > (QEMUD_MAX_NAME_LEN-1))
        return NULL;

    req.data.type = QEMUD_CLIENT_PKT_NETWORK_LOOKUP_BY_NAME;
    strcpy(req.data.qemud_packet_client_data_u.networkLookupByNameRequest.name, name);

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    if (!(network = virGetNetwork(conn,
                                  name,
                                  reply.data.qemud_packet_server_data_u.networkLookupByNameReply.uuid)))
        return NULL;

    return network;
}

static virNetworkPtr qemuNetworkCreateXML(virConnectPtr conn,
                                          const char *xmlDesc) {
    qemud_packet_client req;
    qemud_packet_server reply;
    virNetworkPtr network;
    int len = strlen(xmlDesc);
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    if (len > (QEMUD_MAX_XML_LEN-1)) {
        return NULL;
    }

    req.data.type = QEMUD_CLIENT_PKT_NETWORK_CREATE;
    strcpy(req.data.qemud_packet_client_data_u.networkCreateRequest.xml, xmlDesc);
    req.data.qemud_packet_client_data_u.networkCreateRequest.xml[QEMUD_MAX_XML_LEN-1] = '\0';

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.qemud_packet_server_data_u.networkCreateReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(network = virGetNetwork(conn,
                                  reply.data.qemud_packet_server_data_u.networkCreateReply.name,
                                  reply.data.qemud_packet_server_data_u.networkCreateReply.uuid)))
        return NULL;

    return network;
}


static virNetworkPtr qemuNetworkDefineXML(virConnectPtr conn,
                                          const char *xml) {
    qemud_packet_client req;
    qemud_packet_server reply;
    virNetworkPtr network;
    int len = strlen(xml);
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) conn->networkPrivateData;

    if (len > (QEMUD_MAX_XML_LEN-1)) {
        return NULL;
    }

    req.data.type = QEMUD_CLIENT_PKT_NETWORK_DEFINE;
    strcpy(req.data.qemud_packet_client_data_u.networkDefineRequest.xml, xml);
    req.data.qemud_packet_client_data_u.networkDefineRequest.xml[QEMUD_MAX_XML_LEN-1] = '\0';

    if (qemuProcessRequest(conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.qemud_packet_server_data_u.networkDefineReply.name[QEMUD_MAX_NAME_LEN-1] = '\0';

    if (!(network = virGetNetwork(conn,
                                  reply.data.qemud_packet_server_data_u.networkDefineReply.name,
                                  reply.data.qemud_packet_server_data_u.networkDefineReply.uuid)))
        return NULL;

    return network;
}

static int qemuNetworkUndefine(virNetworkPtr network) {
    qemud_packet_client req;
    qemud_packet_server reply;
    int ret = 0;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.data.type = QEMUD_CLIENT_PKT_NETWORK_UNDEFINE;
    memcpy(req.data.qemud_packet_client_data_u.networkUndefineRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        ret = -1;
        goto cleanup;
    }

 cleanup:
    if (virFreeNetwork(network->conn, network) < 0)
        ret = -1;

    return ret;
}

static int qemuNetworkCreate(virNetworkPtr network) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.data.type = QEMUD_CLIENT_PKT_NETWORK_START;
    memcpy(req.data.qemud_packet_client_data_u.networkStartRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static int qemuNetworkDestroy(virNetworkPtr network) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.data.type = QEMUD_CLIENT_PKT_NETWORK_DESTROY;
    memcpy(req.data.qemud_packet_client_data_u.networkDestroyRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static char * qemuNetworkDumpXML(virNetworkPtr network, int flags ATTRIBUTE_UNUSED) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.data.type = QEMUD_CLIENT_PKT_NETWORK_DUMP_XML;
    memmove(req.data.qemud_packet_client_data_u.networkDumpXMLRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.qemud_packet_server_data_u.networkDumpXMLReply.xml[QEMUD_MAX_XML_LEN-1] = '\0';
 
    return strdup(reply.data.qemud_packet_server_data_u.networkDumpXMLReply.xml);
}

static char * qemuNetworkGetBridgeName(virNetworkPtr network) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.data.type = QEMUD_CLIENT_PKT_NETWORK_GET_BRIDGE_NAME;
    memmove(req.data.qemud_packet_client_data_u.networkGetBridgeNameRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return NULL;
    }

    reply.data.qemud_packet_server_data_u.networkGetBridgeNameReply.ifname[QEMUD_MAX_IFNAME_LEN-1] = '\0';
 
    return strdup(reply.data.qemud_packet_server_data_u.networkGetBridgeNameReply.ifname);
}

static int qemuNetworkGetAutostart(virNetworkPtr network,
                                   int *autostart) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.data.type = QEMUD_CLIENT_PKT_NETWORK_GET_AUTOSTART;
    memmove(req.data.qemud_packet_client_data_u.networkGetAutostartRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    *autostart = reply.data.qemud_packet_server_data_u.networkGetAutostartReply.autostart;

    return 0;
}

static int qemuNetworkSetAutostart(virNetworkPtr network,
                                   int autostart) {
    qemud_packet_client req;
    qemud_packet_server reply;
    qemuNetworkPrivatePtr priv = (qemuNetworkPrivatePtr) network->conn->networkPrivateData;

    req.data.type = QEMUD_CLIENT_PKT_NETWORK_SET_AUTOSTART;
    req.data.qemud_packet_client_data_u.networkSetAutostartRequest.autostart = (autostart != 0);
    memmove(req.data.qemud_packet_client_data_u.networkSetAutostartRequest.uuid, network->uuid, QEMUD_UUID_RAW_LEN);

    if (qemuProcessRequest(network->conn, priv->qemud_fd, NULL, &req, &reply) < 0) {
        return -1;
    }

    return 0;
}

static virDriver qemuDriver = {
    VIR_DRV_QEMU,
    "QEMU",
    LIBVIR_VERSION_NUMBER,
    qemuOpen, /* open */
    qemuClose, /* close */
    NULL, /* type */
    qemuGetVersion, /* version */
    NULL, /* getMaxVcpus */
    qemuNodeGetInfo, /* nodeGetInfo */
    qemuGetCapabilities, /* getCapabilities */
    qemuListDomains, /* listDomains */
    qemuNumOfDomains, /* numOfDomains */
    qemuDomainCreateLinux, /* domainCreateLinux */
    qemuLookupDomainByID, /* domainLookupByID */
    qemuLookupDomainByUUID, /* domainLookupByUUID */
    qemuLookupDomainByName, /* domainLookupByName */
    qemuPauseDomain, /* domainSuspend */
    qemuResumeDomain, /* domainResume */
    qemuShutdownDomain, /* domainShutdown */
    NULL, /* domainReboot */
    qemuDestroyDomain, /* domainDestroy */
    qemuDomainGetOSType, /* domainGetOSType */
    NULL, /* domainGetMaxMemory */
    NULL, /* domainSetMaxMemory */
    NULL, /* domainSetMemory */
    qemuGetDomainInfo, /* domainGetInfo */
    qemuSaveDomain, /* domainSave */
    qemuRestoreDomain, /* domainRestore */
    NULL, /* domainCoreDump */
    NULL, /* domainSetVcpus */
    NULL, /* domainPinVcpu */
    NULL, /* domainGetVcpus */
    NULL, /* domainGetMaxVcpus */
    qemuDomainDumpXML, /* domainDumpXML */
    qemuListDefinedDomains, /* listDomains */
    qemuNumOfDefinedDomains, /* numOfDomains */
    qemuDomainCreate, /* domainCreate */
    qemuDomainDefineXML, /* domainDefineXML */
    qemuUndefine, /* domainUndefine */
    NULL, /* domainAttachDevice */
    NULL, /* domainDetachDevice */
    qemuDomainGetAutostart, /* domainGetAutostart */
    qemuDomainSetAutostart, /* domainSetAutostart */
    NULL, /* domainGetSchedulerType */
    NULL, /* domainGetSchedulerParameters */
    NULL, /* domainSetSchedulerParameters */
};

static virNetworkDriver qemuNetworkDriver = {
    qemuNetworkOpen, /* open */
    qemuNetworkClose, /* close */
    qemuNumOfNetworks, /* numOfNetworks */
    qemuListNetworks, /* listNetworks */
    qemuNumOfDefinedNetworks, /* numOfDefinedNetworks */
    qemuListDefinedNetworks, /* listDefinedNetworks */
    qemuNetworkLookupByUUID, /* networkLookupByUUID */
    qemuNetworkLookupByName, /* networkLookupByName */
    qemuNetworkCreateXML , /* networkCreateXML */
    qemuNetworkDefineXML , /* networkDefineXML */
    qemuNetworkUndefine, /* networkUndefine */
    qemuNetworkCreate, /* networkCreate */
    qemuNetworkDestroy, /* networkDestroy */
    qemuNetworkDumpXML, /* networkDumpXML */
    qemuNetworkGetBridgeName, /* networkGetBridgeName */
    qemuNetworkGetAutostart, /* networkGetAutostart */
    qemuNetworkSetAutostart, /* networkSetAutostart */
};

/**
 * qemuRegister:
 *
 * Registers QEmu/KVM in libvirt driver system
 */
int
qemuRegister (void)
{
    if (virRegisterDriver(&qemuDriver) == -1)
        return -1;
    if (virRegisterNetworkDriver(&qemuNetworkDriver) == -1)
        return -1;

    return 0;
}
#endif /* WITH_QEMU */

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
