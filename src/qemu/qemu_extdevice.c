/*
 * qemu_extdevice.c: QEMU external devices support
 *
 * Copyright (C) 2014, 2018 IBM Corporation
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

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_extdevice")

static int
qemuExtDeviceLogCommand(qemuDomainLogContextPtr logCtxt,
                        virCommandPtr cmd,
                        const char *info)
{
    int ret = -1;
    char *timestamp = NULL;
    char *logline = NULL;
    int logFD;

    logFD = qemuDomainLogContextGetWriteFD(logCtxt);

    if ((timestamp = virTimeStringNow()) == NULL)
        goto cleanup;

    if (virAsprintf(&logline, "%s: Starting external device: %s\n",
                    timestamp, info) < 0)
        goto cleanup;

    if (safewrite(logFD, logline, strlen(logline)) < 0)
        goto cleanup;

    virCommandWriteArgLog(cmd, logFD);

    ret = 0;

 cleanup:
    VIR_FREE(timestamp);
    VIR_FREE(logline);

    return ret;
}

static int qemuExtTPMInitPaths(virQEMUDriverPtr driver,
                               virDomainDefPtr def)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int ret = 0;

    switch (def->tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        ret = virTPMEmulatorInitPaths(def->tpm, cfg->swtpmStorageDir, def->name);
        break;
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}

static int qemuExtTPMPrepareHost(virQEMUDriverPtr driver,
                                 virDomainDefPtr def)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int ret = 0;

    switch (def->tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        ret = virTPMEmulatorPrepareHost(def->tpm, cfg->swtpmLogDir,
                                        def->name, cfg->swtpm_user,
                                        cfg->swtpmStateDir, cfg->user);
        break;
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}

/*
 * qemuExtTPMStartEmulator:
 *
 * @driver: QEMU driver
 * @def: domain definition
 * @logCtxt: log context
 *
 * Start the external TPM Emulator:
 * - have the command line built
 * - start the external TPM Emulator and sync with it before QEMU start
 */
static int
qemuExtTPMStartEmulator(virQEMUDriverPtr driver,
                        virDomainDefPtr def,
                        qemuDomainLogContextPtr logCtxt)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    int exitstatus;
    char *errbuf = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virDomainTPMDefPtr tpm = def->tpm;

    /* stop any left-over TPM emulator for this VM */
    virTPMEmulatorStop(cfg->swtpmStateDir, def->name);

    if (!(cmd = virTPMEmulatorBuildCommand(tpm, def->name, def->uuid,
                                           cfg->swtpm_user)))
        goto cleanup;

    if (qemuExtDeviceLogCommand(logCtxt, cmd, "TPM Emulator") < 0)
        goto cleanup;

    virCommandSetErrorBuffer(cmd, &errbuf);

    if (virCommandRun(cmd, &exitstatus) < 0 || exitstatus != 0) {
        VIR_ERROR("Could not start 'swtpm'. exitstatus: %d\n"
                  "stderr: %s\n", exitstatus, errbuf);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not start 'swtpm'. exitstatus: %d, "
                       "error: %s"), exitstatus, errbuf);
        goto error;
    }

    ret = 0;

 cleanup:
    VIR_FREE(errbuf);
    virCommandFree(cmd);

    virObjectUnref(cfg);

    return ret;

 error:
    virTPMEmulatorStop(cfg->swtpmStateDir, def->name);
    VIR_FREE(tpm->data.emulator.source.data.nix.path);

    goto cleanup;
}

static int
qemuExtTPMStart(virQEMUDriverPtr driver,
                virDomainDefPtr def,
                qemuDomainLogContextPtr logCtxt)
{
    int ret = 0;
    virDomainTPMDefPtr tpm = def->tpm;

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        ret = qemuExtTPMStartEmulator(driver, def, logCtxt);
        break;
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    return ret;
}

static void
qemuExtTPMStop(virQEMUDriverPtr driver, virDomainDefPtr def)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    switch (def->tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_EMULATOR:
        virTPMEmulatorStop(cfg->swtpmStateDir, def->name);
        break;
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }
}

/*
 * qemuExtDevicesInitPaths:
 *
 * @driver: QEMU driver
 * @def: domain definition
 *
 * Initialize paths of external devices so that it is known where state is
 * stored and we can remove directories and files in case of domain XML
 * changes.
 */
int qemuExtDevicesInitPaths(virQEMUDriverPtr driver,
                            virDomainDefPtr def)
{
    int ret = 0;

    if (def->tpm)
        ret = qemuExtTPMInitPaths(driver, def);

    return ret;
}

/*
 * qemuExtDevicesPrepareHost:
 *
 * @driver: QEMU driver
 * @def: domain definition
 *
 * Prepare host storage paths for external devices.
 */
int qemuExtDevicesPrepareHost(virQEMUDriverPtr driver,
                              virDomainDefPtr def)
{
    int ret = 0;

    if (def->tpm)
        ret = qemuExtTPMPrepareHost(driver, def);

    return ret;
}

int
qemuExtDevicesStart(virQEMUDriverPtr driver,
                    virDomainDefPtr def,
                    qemuDomainLogContextPtr logCtxt)
{
    int ret = 0;

    if (def->tpm)
        ret = qemuExtTPMStart(driver, def, logCtxt);

    return ret;
}

void
qemuExtDevicesStop(virQEMUDriverPtr driver,
                   virDomainDefPtr def)
{
     if (def->tpm)
         qemuExtTPMStop(driver, def);
}
