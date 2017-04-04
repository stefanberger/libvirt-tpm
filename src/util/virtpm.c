/*
 * virtpm.c: TPM support
 *
 * Copyright (C) 2013,2018 IBM Corporation
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cap-ng.h>

#include "conf/domain_conf.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virstring.h"
#include "virerror.h"
#include "viralloc.h"
#include "virfile.h"
#include "virkmod.h"
#include "virlog.h"
#include "virtpm.h"
#include "virutil.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.tpm")

/*
 * executables for the swtpm; to be found on the host
 */
static char *swtpm_path;
static char *swtpm_setup;
static char *swtpm_ioctl;

/**
 * virTPMCreateCancelPath:
 * @devpath: Path to the TPM device
 *
 * Create the cancel path given the path to the TPM device
 */
char *
virTPMCreateCancelPath(const char *devpath)
{
    char *path = NULL;
    const char *dev;
    const char *prefix[] = {"misc/", "tpm/"};
    size_t i;

    if (devpath) {
        dev = strrchr(devpath, '/');
        if (dev) {
            dev++;
            for (i = 0; i < ARRAY_CARDINALITY(prefix); i++) {
                if (virAsprintf(&path, "/sys/class/%s%s/device/cancel",
                                prefix[i], dev) < 0)
                     goto cleanup;

                if (virFileExists(path))
                    break;

                VIR_FREE(path);
            }
            if (!path)
                ignore_value(VIR_STRDUP(path, "/dev/null"));
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("TPM device path %s is invalid"), devpath);
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing TPM device path"));
    }

 cleanup:
    return path;
}

/*
 * virTPMEmulatorInit
 *
 * Initialize the Emulator functions by searching for necessary
 * executables that we will use to start and setup the swtpm
 */
static int
virTPMEmulatorInit(void)
{
    if (!swtpm_path) {
        swtpm_path = virFindFileInPath("swtpm");
        if (!swtpm_path) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not find swtpm 'swtpm' in PATH"));
            return -1;
        }
        if (!virFileIsExecutable(swtpm_path)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("TPM emulator %s is not an executable"),
                           swtpm_path);
            VIR_FREE(swtpm_path);
            return -1;
        }
    }

    if (!swtpm_setup) {
        swtpm_setup = virFindFileInPath("swtpm_setup");
        if (!swtpm_setup) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not find 'swtpm_setup' in PATH"));
            return -1;
        }
        if (!virFileIsExecutable(swtpm_setup)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("'%s' is not an executable"),
                           swtpm_setup);
            VIR_FREE(swtpm_setup);
            return -1;
        }
    }

    if (!swtpm_ioctl) {
        swtpm_ioctl = virFindFileInPath("swtpm_ioctl");
        if (!swtpm_ioctl) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not find swtpm_ioctl in PATH"));
            return -1;
        }
        if (!virFileIsExecutable(swtpm_ioctl)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("swtpm_ioctl program %s is not an executable"),
                           swtpm_ioctl);
            VIR_FREE(swtpm_ioctl);
            return -1;
        }
    }

    return 0;
}

/*
 * virTPMCreateEmulatorStoragePath
 *
 * @swtpmStorageDir: directory for swtpm persistent state
 * @vmname: The name of the VM for which to create the storage
 *
 * Create the swtpm's storage path
 */
static char *
virTPMCreateEmulatorStoragePath(const char *swtpmStorageDir,
                                const char *vmname)
{
    char *path = NULL;

    ignore_value(virAsprintf(&path, "%s/%s", swtpmStorageDir, vmname));

    return path;
}

/*
 * virtTPMGetSwtpmStorageDir:
 *
 * @storagepath: directory for swtpm's pesistent state
 *
 * Derive the 'swtpmStorageDir' from the storagepath.
 */
static char *
virTPMGetSwtpmStorageDir(const char *storagepath)
{
    const char *tail = strrchr(storagepath, '/');
    char *path = NULL;

    if (!tail) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get tail of storagedir %s"),
                       storagepath);
        return NULL;
    }
    ignore_value(VIR_STRNDUP(path, storagepath, tail - storagepath));

    return path;
}

/*
 * virTPMEmulatorInitStorage
 *
 * Initialize the TPM Emulator storage by creating its root directory,
 * which is typically found in /var/lib/libvirt/tpm.
 *
 */
static int
virTPMEmulatorInitStorage(const char *swtpmStorageDir)
{
    int rc = 0;

    /* allow others to cd into this dir */
    if (virFileMakePathWithMode(swtpmStorageDir, 0711) < 0) {
        virReportSystemError(errno,
                             _("Could not create TPM directory %s"),
                             swtpmStorageDir);
        rc = -1;
    }

    return rc;
}

/*
 * virTPMCreateEmulatorStorage
 *
 * @storagepath: directory for swtpm's pesistent state
 * @vmname: The name of the VM
 * @created: a pointer to a bool that will be set to true if the
 *           storage was created because it did not exist yet
 * @userid: The userid that needs to be able to access the directory
 *
 * Unless the storage path for the swtpm for the given VM
 * already exists, create it and make it accessible for the given userid.
 * Adapt ownership of the directory and all swtpm's state files there.
 */
static int
virTPMCreateEmulatorStorage(const char *storagepath,
                            bool *created,
                            uid_t swtpm_user)
{
    int ret = -1;
    char *swtpmStorageDir = virTPMGetSwtpmStorageDir(storagepath);

    if (!swtpmStorageDir)
        return -1;

    if (virTPMEmulatorInitStorage(swtpmStorageDir) < 0)
        return -1;

    *created = false;

    if (!virFileExists(storagepath))
        *created = true;

    if (virDirCreate(storagepath, 0700, swtpm_user, swtpm_user,
                     VIR_DIR_CREATE_ALLOW_EXIST) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not create directory %s as uid %u"),
                       storagepath, swtpm_user);
        goto cleanup;
    }

    if (virDirChownFiles(storagepath, swtpm_user, swtpm_user) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(swtpmStorageDir);

    return ret;
}

void
virTPMDeleteEmulatorStorage(const char *path)
{
    ignore_value(virFileDeletePath(path));
}

/*
 * virTPMCreateEmulatorSocket:
 *
 * @swtpmStateDir: the directory where to create the socket in
 *
 * Create the vTPM device name from the given parameters
 */
static char *
virTPMCreateEmulatorSocket(const char *swtpmStateDir, const char *vmname)
{
    char *path = NULL;

    ignore_value(virAsprintf(&path, "%s/%s-swtpm.sock", swtpmStateDir,
                             vmname));

    return path;
}

/*
 * virTPMEmulatorInitPaths:
 *
 * @tpm: TPM definition for an emulator type
 * @swtpmStorageDir: the general swtpm storage dir which is used as a base
 *                   directory for creating VM specific directories
 * @vmname: the name of the VM
 */
int virTPMEmulatorInitPaths(virDomainTPMDefPtr tpm,
                            const char *swtpmStorageDir,
                            const char *vmname)
{
    if (!tpm->data.emulator.storagepath &&
        !(tpm->data.emulator.storagepath =
            virTPMCreateEmulatorStoragePath(swtpmStorageDir, vmname)))
        return -1;

    return 0;
}

/*
 * virTPMEmulatorPrepareHost:
 *
 * @tpm: tpm definition
 * @logDir: directory where swtpm writes its logs into
 * @vmname: name of the VM
 * @swtpm_user: uid to run the swtpm with
 * @swtpmStateDir: directory for swtpm's persistent state
 * @qemu_user: uid that qemu will run with; we share the socket file with it
 *
 * Prepare the log directory for the swtpm and adjust ownership of it and the
 * log file we will be using. Prepare the state directory where we will share
 * the socket between tss and qemu users.
 */
int virTPMEmulatorPrepareHost(virDomainTPMDefPtr tpm,
                              const char *logDir, const char *vmname,
                              uid_t swtpm_user, const char *swtpmStateDir,
                              uid_t qemu_user)
{
    int ret = -1;

    if (virTPMEmulatorInit() < 0)
        return -1;

    /* create log dir ... */
    if (virFileMakePathWithMode(logDir, 0771) < 0)
        goto cleanup;

    /* ... and adjust ownership */
    if (virDirCreate(logDir, 0771, swtpm_user, swtpm_user,
                     VIR_DIR_CREATE_ALLOW_EXIST) < 0)
        goto cleanup;

    /* create logfile name ... */
    if (virAsprintf(&tpm->data.emulator.logfile, "%s/%s-swtpm.log",
                    logDir, vmname) < 0)
        goto cleanup;

    /* ... and make sure it can be accessed by swtpm_user */
    if (virFileExists(tpm->data.emulator.logfile) &&
        chown(tpm->data.emulator.logfile, swtpm_user, swtpm_user) < 0) {
        virReportSystemError(errno,
                             _("Could not chown on swtpm logfile %s"),
                             tpm->data.emulator.logfile);
        goto cleanup;
    }

    /* create our swtpm state dir ... */
    if (virDirCreate(swtpmStateDir, 0771, qemu_user, swtpm_user,
                     VIR_DIR_CREATE_ALLOW_EXIST) < 0)
        goto cleanup;

    /* create the socket filename */
    if (!(tpm->data.emulator.source.data.nix.path =
          virTPMCreateEmulatorSocket(swtpmStateDir, vmname)))
        goto cleanup;
    tpm->data.emulator.source.type = VIR_DOMAIN_CHR_TYPE_UNIX;

    ret = 0;

 cleanup:
    if (ret)
        VIR_FREE(tpm->data.emulator.logfile);

    return ret;
}

/*
 * virTPMEmulatorRunSetup
 *
 * @storagepath: path to the directory for TPM state
 * @vmname: the name of the VM
 * @vmuuid: the UUID of the VM
 * @swtpm_user: The userid to switch to when setting up the TPM;
 *              typically this should be the uid of 'tss' or 'root'
 * @logfile: The file to write the log into; it must be writable
 *           for the user given by userid or 'tss'
 *
 * Setup the external swtpm
 */
static int
virTPMEmulatorRunSetup(const char *storagepath, const char *vmname,
                       const unsigned char *vmuuid,
                       uid_t swtpm_user, const char *logfile)
{
    virCommandPtr cmd = NULL;
    int exitstatus;
    int rc = 0;
    char uuid[VIR_UUID_STRING_BUFLEN];
    char *vmid = NULL;

    cmd = virCommandNew(swtpm_setup);
    if (!cmd) {
        rc = -1;
        goto cleanup;
    }

    virUUIDFormat(vmuuid, uuid);
    if (virAsprintf(&vmid, "%s:%s", vmname, uuid) < 0)
        goto cleanup;

    virCommandSetUID(cmd, swtpm_user);
    virCommandSetGID(cmd, swtpm_user);

    virCommandAddArgList(cmd,
                         "--tpm-state", storagepath,
                         "--vmid", vmid,
                         "--logfile", logfile,
                         "--createek",
                         "--create-ek-cert",
                         "--create-platform-cert",
                         "--lock-nvram",
                         "--not-overwrite",
                         NULL);

    virCommandClearCaps(cmd);

    if (virCommandRun(cmd, &exitstatus) < 0 || exitstatus != 0) {
        char *buffer = NULL;
        ignore_value(virFileReadAllQuiet(logfile, 10240, &buffer));

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not run '%s'. exitstatus: %d;\n"
                         "%s"),
                       swtpm_setup, exitstatus, buffer);
        VIR_FREE(buffer);
        rc = -1;
    }

 cleanup:
    VIR_FREE(vmid);
    virCommandFree(cmd);

    return rc;
}

/*
 * virTPMEmulatorBuildCommand:
 *
 * @tpm: TPM definition
 * @vmname: The name of the VM
 * @vmuuid: The UUID of the VM
 * @swtpm_user: The uid for the swtpm to run as (drop privileges to from root)
 *
 * Create the virCommand use for starting the emulator
 * Do some initializations on the way, such as creation of storage
 * and emulator setup.
 */
virCommandPtr
virTPMEmulatorBuildCommand(virDomainTPMDefPtr tpm, const char *vmname,
                           const unsigned char *vmuuid, uid_t swtpm_user)
{
    virCommandPtr cmd = NULL;
    bool created = false;

    if (virTPMCreateEmulatorStorage(tpm->data.emulator.storagepath,
                                    &created, swtpm_user) < 0)
        return NULL;

    if (created &&
        virTPMEmulatorRunSetup(tpm->data.emulator.storagepath, vmname, vmuuid,
                               swtpm_user, tpm->data.emulator.logfile) < 0)
        goto error;

    unlink(tpm->data.emulator.source.data.nix.path);

    cmd = virCommandNew(swtpm_path);
    if (!cmd)
        goto error;

    virCommandClearCaps(cmd);

    virCommandAddArgList(cmd, "socket", "--daemon", "--ctrl", NULL);
    virCommandAddArgFormat(cmd, "type=unixio,path=%s,mode=0660",
                           tpm->data.emulator.source.data.nix.path);

    virCommandAddArg(cmd, "--tpmstate");
    virCommandAddArgFormat(cmd, "dir=%s,mode=0640",
                           tpm->data.emulator.storagepath);

    virCommandAddArg(cmd, "--log");
    virCommandAddArgFormat(cmd, "file=%s", tpm->data.emulator.logfile);

    virCommandSetUID(cmd, swtpm_user);
    virCommandSetGID(cmd, swtpm_user);

    return cmd;

 error:
    if (created)
        virTPMDeleteEmulatorStorage(tpm->data.emulator.storagepath);

    VIR_FREE(tpm->data.emulator.source.data.nix.path);
    VIR_FREE(tpm->data.emulator.storagepath);

    virCommandFree(cmd);

    return NULL;
}

/*
 * virTPMEmulatorStop
 * @swtpmStateDir: A directory where the socket is located
 * @vmname: name of the VM
 *
 * Gracefully stop the swptm
 */
void
virTPMEmulatorStop(const char *swtpmStateDir, const char *vmname)
{
    virCommandPtr cmd;
    char *pathname;
    char *errbuf = NULL;

    if (virTPMEmulatorInit() < 0)
        return;

    if (!(pathname = virTPMCreateEmulatorSocket(swtpmStateDir, vmname)))
        return;

    if (!virFileExists(pathname))
        goto cleanup;

    cmd = virCommandNew(swtpm_ioctl);
    if (!cmd) {
        VIR_FREE(pathname);
        return;
    }

    virCommandAddArgList(cmd, "--unix", pathname, "-s", NULL);

    virCommandSetErrorBuffer(cmd, &errbuf);

    ignore_value(virCommandRun(cmd, NULL));

    virCommandFree(cmd);

    /* clean up the socket */
    unlink(pathname);

 cleanup:
    VIR_FREE(pathname);
    VIR_FREE(errbuf);
}
