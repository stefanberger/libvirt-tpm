/*
 * qemu_extdevice.c: QEMU external devices support
 *
 * Copyright (C) 2014 IBM Corporation
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Stefan Berger <stefanb@linux.vnet.ibm.com>
 */

#include <config.h>

#include "qemu_extdevice.h"
#include "qemu_domain.h"

#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virtime.h"
#include "virtpm.h"
#include "tpm/virtpm_backend.h"
#include "virpidfile.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_extdevice")

static char *
virExtDevicePidFileBuild(const char *stateDir,
                         const char *vmname,
                         const char *device)
{
    char *pidfile = NULL;
    char *devname = NULL;

    if (virAsprintf(&devname, "%s-%s", vmname, device) < 0)
        return NULL;

    pidfile = virPidFileBuildPath(stateDir, devname);

    VIR_FREE(devname);

    return pidfile;
}

static int
qemuExtDeviceLogCommand(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        virCommandPtr cmd,
                        const char *info)
{
    int ret = -1;
    int logfile;
    char *timestamp = NULL;
    char *logline = NULL;

    if ((logfile = qemuDomainCreateLog(driver, vm, false)) < 0 )
        goto cleanup;

    if ((timestamp = virTimeStringNow()) == NULL)
        goto cleanup;

    if (virAsprintf(&logline, "%s: Starting external device: %s\n",
                    timestamp, info) < 0)
        goto cleanup;

    if (safewrite(logfile, logline, strlen(logline)) < 0)
        goto cleanup;

    virCommandWriteArgLog(cmd, logfile);

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(logfile);
    VIR_FREE(timestamp);
    VIR_FREE(logline);

    return ret;
}


/*
 * qemuExtTPMStartCuseTPM:
 *
 * @comm: virConnect pointer
 * @driver: QEMU driver
 * @vm: domain object
 *
 * Start the external CUSE TPM:
 * - have the command line built
 * - start the external CUSE TPM and sync with it before QEMU start
 */
static int
qemuExtTPMStartCuseTPM(virConnectPtr conn ATTRIBUTE_UNUSED,
                       virQEMUDriverPtr driver,
                       virDomainObjPtr vm)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    int exitstatus;
    char *errbuf = NULL;
    int logfile = -1;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virDomainDefPtr def = vm->def;
    virDomainDefPtr newDef = vm->newDef;
    unsigned char *vmuuid = def->uuid;
    virDomainTPMDefPtr tpm = def->tpm;
    unsigned char *secret = NULL;
    size_t secret_size;
    char *pidfile = NULL;

    /* stop any left-over Cuse TPM for this VM */
    virTPMStopCuseTPM(tpm, vmuuid, false);

    /* setup encryption if needed */
    /* in case of migration newDef is NULL, so we use def then */
    if (virTPMSetupEncryption(conn, newDef ? newDef : def, cfg->configDir,
                              &secret, &secret_size) < 0)
        goto cleanup;

    if (!(pidfile = virExtDevicePidFileBuild(cfg->stateDir,
                                             vm->def->name, "swtpm_cuse")))
        goto cleanup;

    if (!(cmd = virTPMCuseTPMBuildCommand(tpm, vmuuid, cfg->swtpm_cuse_user,
                                          secret, secret_size,
                                          pidfile)))
        goto error;

    if (qemuExtDeviceLogCommand(driver, vm, cmd, "CUSE TPM") < 0)
        goto cleanup;

    virCommandSetErrorBuffer(cmd, &errbuf);

    if (virSecurityManagerSetTPMLabels(driver->securityManager,
                                       def) < 0)
        goto error;

    if (virSecurityManagerSetChildProcessLabel(driver->securityManager,
                                               def, cmd) < 0)
        goto error;

    if (virSecurityManagerPreFork(driver->securityManager) < 0)
        goto error;

    /*
     * make sure we run this as root
     * note: when installing libvirtd via make install we don't need this,
     *       but when installed from RPM, this is necessary.
     */
    virCommandSetUID(cmd, 0);
    virCommandSetGID(cmd, 0);

    ret = virCommandRun(cmd, &exitstatus);

    virSecurityManagerPostFork(driver->securityManager);

    if (ret < 0 || exitstatus != 0) {
        VIR_ERROR("Could not start the cuse-tpm. exitstatus: %d\n"
                  "stderr: %s\n", exitstatus, errbuf);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not start the cuse-tpm. exitstatus: %d, "
                       "error: %s"), exitstatus, errbuf);
        ret = -1;
        goto error;
    }

    /* sync the startup of the CUSE TPM's /dev/vtpm* with the start of QEMU */
    if (virTPMTryConnect(tpm->data.cuse.source.data.file.path,
                         3 * 1000 * 1000) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not connect to the cuse-tpm on '%s'"),
                       tpm->data.cuse.source.data.file.path);
        goto error;
    }

    if (virFileWaitAvailable(pidfile, 1000) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find cuse-tpm's pidfile '%s'"),
                       pidfile);
        goto error;
    }

    VIR_FREE(tpm->data.cuse.pidfile);
    tpm->data.cuse.pidfile = pidfile;
    pidfile = NULL;

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(logfile);
    VIR_FREE(errbuf);
    virCommandFree(cmd);
    VIR_FREE(secret);

    virObjectUnref(cfg);

    return ret;

 error:
    if (def->tpm->data.cuse.pwdfile) {
        unlink(def->tpm->data.cuse.pwdfile);
        VIR_FREE(def->tpm->data.cuse.pwdfile);
    }
    virTPMStopCuseTPM(tpm, vmuuid, false);
    VIR_FREE(tpm->data.cuse.source.data.file.path);
    VIR_FREE(pidfile);

    goto cleanup;
}


static int
qemuExtTPMStart(virConnectPtr conn,
                virQEMUDriverPtr driver,
                virDomainObjPtr vm)
{
    int ret = 0;
    virDomainTPMDefPtr tpm = vm->def->tpm;

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_CUSE_TPM:
        ret = qemuExtTPMStartCuseTPM(conn, driver, vm);
        break;
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}

static void
qemuExtTPMStop(virDomainObjPtr vm)
{
    switch (vm->def->tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_CUSE_TPM:
        virTPMStopCuseTPM(vm->def->tpm, vm->def->uuid, false);
        break;
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }
}

int
qemuExtDevicesStart(virConnectPtr conn,
                    virQEMUDriverPtr driver,
                    virDomainObjPtr vm)
{
    int ret = 0;

    if (vm->def->tpm)
        ret = qemuExtTPMStart(conn, driver, vm);

    return ret;
}

void
qemuExtDevicesStop(virDomainObjPtr vm)
{
     if (vm->def->tpm)
         qemuExtTPMStop(vm);
}
