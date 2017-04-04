/*
 * virtpm.c: TPM support
 *
 * Copyright (C) 2013 IBM Corporation
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

#include "domain_conf.h"
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
 * executables for the CUSE TPM; to be found on the host
 */
static char *swtpm_cuse;
static char *swtpm_setup;
static char *swtpm_ioctl;

static bool swtpm_supports_tpm2;

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
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("No usable sysfs TPM cancel file could be "
                                 "found"));
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
 * virTPMCheckForTPM2Support
 *
 * Check whether swtpm_setup supports TPM 2
 */
static void
virTPMCheckForTPM2Support(void)
{
    virCommandPtr cmd;
    char *help = NULL;

    if (!swtpm_setup)
        return;

    cmd = virCommandNew(swtpm_setup);
    if (!cmd)
        return;

    virCommandAddArg(cmd, "--help");
    virCommandSetOutputBuffer(cmd, &help);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (strstr(help, "--tpm2")) {
        fprintf(stderr, "TPM2 is supported by swtpm_setup\n");
        swtpm_supports_tpm2 = true;
    }

 cleanup:
    virCommandFree(cmd);
    VIR_FREE(help);
}

/*
 * virTPMCuseInit
 *
 * Initialize the CUSE TPM functions by searching for necessary
 * executables that we will use to start and setup the CUSE TPM
 */
static int
virTPMCuseInit(void)
{
    char *errbuf = NULL;

    if (!swtpm_cuse) {
        swtpm_cuse = virFindFileInPath("swtpm_cuse");
        if (!swtpm_cuse) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not find CUSE TPM 'swtpm_cuse' in PATH"));
            return -1;
        }
        if (!virFileIsExecutable(swtpm_cuse)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("CUSE TPM %s is not an executable"),
                           swtpm_cuse);
            VIR_FREE(swtpm_cuse);
            return -1;
        }
    }

    if (swtpm_cuse) {
        if ((errbuf = virKModLoad("cuse", true))) {
            /* non fatal in case it's built-in */
            VIR_WARN("Is cuse module built-in? failed to load cuse module : %s", errbuf);
            VIR_FREE(errbuf);
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
        virTPMCheckForTPM2Support();
    }

    if (!swtpm_ioctl) {
        swtpm_ioctl = virFindFileInPath("swtpm_ioctl");
        if (!swtpm_ioctl) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Could not find TPM IOCTL swtpm_ioctl in PATH"));
            return -1;
        }
        if (!virFileIsExecutable(swtpm_ioctl)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("CUSE TPM ioctl program %s is not an executable"),
                           swtpm_ioctl);
            VIR_FREE(swtpm_ioctl);
            return -1;
        }
    }
    return 0;
}

/*
 * virTPMCreateCuseTPMStoragePath
 *
 * @vmuuid: The UUID of the VM for which to create the storage;
 *          may be NULL
 * @suffix: A suffix to append to the storage path; this can be
 *          used to create a file path
 *
 * Create the CUSE TPM's storage path
 */
static char *
virTPMCreateCuseTPMStoragePath(const unsigned char *vmuuid,
                               const char *suffix)
{
    char *path = NULL;
    char uuid[VIR_UUID_STRING_BUFLEN];

    if (vmuuid)
        virUUIDFormat(vmuuid, uuid);
    else
        uuid[0] = '\0';

    if (virAsprintf(&path,
                    "%s/lib/libvirt/tpm/%s%s",
                    LOCALSTATEDIR, uuid, suffix) < 0)
        virReportOOMError();

    return path;
}

/*
 * virTPMExistsCuseTPMStorage
 *
 * vmuuid: The UUID of the VM for which to check for existing CUSE
 *         TPM storage
 *
 * Check whether CUSE TPM storage already exists for a given VM.
 * Returns -1 on error, 0 if no storage exists and 1 if the storage
 * already exists.
 */
int
virTPMExistsCuseTPMStorage(const unsigned char *vmuuid)
{
    int rc = 0;
    char *path = NULL;

    if (!vmuuid)
        return 0;

    if (!(path = virTPMCreateCuseTPMStoragePath(vmuuid, "")))
        return -1;

    if (virFileExists(path))
        rc = 1;

    VIR_FREE(path);

    return rc;
}

/*
 * virTPMCuseInitStorage
 *
 * Initialize the CUSE TPM storage by creating its root directory,
 * which is typically found in /var/lib/libvirt/tpm.
 *
 */
static int
virTPMCuseInitStorage(void)
{
    char *path = NULL;
    int rc = 0;

    if (!(path = virTPMCreateCuseTPMStoragePath(NULL, "")))
        return -1;

    if (virFileExists(path))
        goto cleanup;

    /* allow others to cd into this dir */
    if (virFileMakePathWithMode(path, 0711) < 0) {
        virReportSystemError(errno,
                             _("Could not create TPM directory %s"),
                             path);
        rc = -1;
    }

 cleanup:
    VIR_FREE(path);

    return rc;
}

/*
 * virTPMCreateCuseTPMStorage
 *
 * @vmuuid: The UUID of the VM
 * @created: a pointer to a bool that will be set to true if the
 *           storage was created because it did not exist yet
 * @userid: The userid that needs to be able to access the directory
 *
 * Unless the storage path for the CUSE TPM for the given VM
 * already exists, create it and make it accessible for the given userid.
 */
static char *
virTPMCreateCuseTPMStorage(const unsigned char *vmuuid, bool *created,
                           const char *userid)
{
    char *path;
    uid_t uid;
    gid_t gid;
    mode_t mode;

    if (virTPMCuseInitStorage() < 0)
        return NULL;

    *created = false;

    if (!(path = virTPMCreateCuseTPMStoragePath(vmuuid, "")))
        return NULL;

    if (virFileExists(path))
        goto exit;

    *created = true;

    if (virGetUserID(userid, &uid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get uid for user %s"),
                       userid);
        VIR_FREE(path);
        goto exit;
    }

    if (virGetGroupID(userid, &gid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get gid for group %s"),
                       userid);
        VIR_FREE(path);
        goto exit;
    }

    mode = S_IRUSR | S_IWUSR | S_IXUSR;

    if (virDirCreate(path, mode, uid, gid, 0) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not create directory %s as user %s"),
                       path, userid);
        VIR_FREE(path);
    }

 exit:
    return path;
}

void
virTPMDeleteCuseTPMStorage(const unsigned char *vmuuid)
{
    char *path;

    if (!(path = virTPMCreateCuseTPMStoragePath(vmuuid, "")))
        return;

    ignore_value(virFileDeletePath(path));
    VIR_FREE(path);
}


/*
 * virTPMCreateVTPMDeviceName:
 *
 * @prefix: a prefix to prepend
 * @uuid: the UUID of the VM
 *
 * Create the vTPM device name from the given parameters
 */
static char *
virTPMCreateVTPMDeviceName(const char *prefix, unsigned const char *vmuuid)
{
    char *p;
    char uuid[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(vmuuid, uuid);
    if (virAsprintf(&p, "%svtpm-%s", prefix, uuid) < 0)
        virReportOOMError();

    return p;
}

/*
 * virTPMTryConnect
 *
 * @pathname: The device pathname to try to open()
 * @timeout_ms: The time in ms to spend trying to connect
 *
 * Try to connect to the given device pathname using open().
 */
int
virTPMTryConnect(const char *pathname, unsigned long timeout_ms)
{
    return virFileWaitAvailable(pathname, timeout_ms);
}

/*
 * virTPMSetupCuseTPM
 *
 * @storagepath: path to the directory for TPM state
 * @vmuuid: the UUID of the VM
 * @userid: The userid to switch to when setting up the TPM;
 *          typically this should be 'tss'
 * @logfile: The file to write the log into; it must be writable
 *           for the user given by userid or 'tss'
 * @pwdfile: Path to file containing the TPM state encryption passphrase
 * @tpmversion: The version of the TPM, either a TPM 1.2 or TPM 2
 *
 * Setup the external CUSE TPM
 */
static int
virTPMSetupCuseTPM(const char *storagepath, const unsigned char *vmuuid,
                   const char *userid, const char *logfile,
                   const char *pwdfile, const virDomainTPMVersion tpmversion)
{
    virCommandPtr cmd = NULL;
    int exitstatus;
    int rc = 0;
    char uuid[VIR_UUID_STRING_BUFLEN];

    cmd = virCommandNew(swtpm_setup);
    if (!cmd) {
        rc = -1;
        goto cleanup;
    }

    virUUIDFormat(vmuuid, uuid);

    if (userid)
        virCommandAddArgList(cmd, "--runas", userid, NULL);
    if (pwdfile)
        virCommandAddArgList(cmd, "--pwdfile", pwdfile, NULL);
    switch (tpmversion) {
    case VIR_DOMAIN_TPM_VERSION_1_2:
        break;
    case VIR_DOMAIN_TPM_VERSION_2:
        virCommandAddArgList(cmd, "--tpm2", NULL);
        if (!swtpm_supports_tpm2) {
            fprintf(stderr, "SKIPPING swtpm_setup for tpm2 for now!\n");
            goto cleanup;
        }
        break;
    }
    virCommandAddArgList(cmd,
                         "--tpm-state", storagepath,
                         "--vmid", uuid,
                         "--logfile", logfile,
                         "--createek",
                         "--create-ek-cert",
                         "--create-platform-cert",
                         "--lock-nvram",
                         NULL);

    virCommandClearCaps(cmd);

    if (virCommandRun(cmd, &exitstatus) < 0 || exitstatus != 0) {
        /* copy the log to libvirt error since the log will be deleted */
        char *buffer = NULL;
        ignore_value(virFileReadAllQuiet(logfile, 10240, &buffer));
        VIR_ERROR(_("Error setting up CUSE TPM:\n%s"), buffer);
        VIR_FREE(buffer);

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not run '%s'. exitstatus: %d; "
                         "please check the libvirt error log"),
                       swtpm_setup, exitstatus);
        rc = -1;
    }
    virCommandFree(cmd);

 cleanup:

    return rc;
}

/*
 * virTPMWriteSecretToFile
 *
 * userid: The userid who must be able to access the fil
 * secret: The actual secret
 * secret_size: The length of the secret
 *
 * Write the secret into a file that is accessible by the given
 * user. Returns the path to the file or NULL in case of failure.
 */
static char *
virTPMWriteSecretToFile(const char *userid, const unsigned char *secret,
                        size_t secret_size)
{
    uid_t uid;
    gid_t gid;
    int fd = -1;
    char *pwdfile = NULL;
    bool unlink_pwdfile = false;

    if (virAsprintf(&pwdfile, "/tmp/pwdfile.XXXXXX") < 0)
        return NULL;

    fd = mkostemp(pwdfile, O_WRONLY);

    if (fd < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not create temporary file"));
        goto error;
    }
    unlink_pwdfile = true;

    if (virGetUserID(userid, &uid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get uid for user %s"),
                       userid);
        goto error;
    }

    if (virGetGroupID(userid, &gid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get gid for group %s"),
                       userid);
        goto error;
    }

    if (fchown(fd, uid, gid) < 0) {
        virReportSystemError(errno, "%s",
                             _("Error changing file ownership"));
        goto error;
    }

    if (safewrite(fd, secret, secret_size) < 0) {
        virReportSystemError(errno, _("cannot write to file '%s'"),
                             pwdfile);
        goto error;
    }

    VIR_FORCE_CLOSE(fd);

    return pwdfile;

 error:
    if (unlink_pwdfile)
        unlink(pwdfile);
    VIR_FREE(pwdfile);
    VIR_FORCE_CLOSE(fd);

    return NULL;
}

/*
 * virTPMBuildCuseTPMCommand
 *
 * @tpm: TPM definition
 * @vmuuid: The UUID of the VM
 * @userid: The user id to use for the CUSE TPM to drop priviliges to
 * @secret: The passphrase to use for TPM state encryption
 * @secret_size: The length of the passphrase
 * @pidfile: The pidfile to use
 *
 * Create the virCommand use for starting the CUSE TPM
 * Do some initializations on the way, such as creation of storage
 * and CUSE TPM setup.
 * The pwdfile name will be stored in the TPM definition.
 */
virCommandPtr
virTPMCuseTPMBuildCommand(virDomainTPMDefPtr tpm, const unsigned char *vmuuid,
                          const char *userid,
                          const unsigned char *secret, size_t secret_size,
                          const char *pidfile)
{
    virCommandPtr cmd = NULL;
    char *storagepath = NULL;
    char *logfile = NULL;
    char *pwdfile = NULL;
    char *devname = NULL;
    bool created = false;

    if (virTPMCuseInit() < 0)
        return NULL;

    /* passing the secret via a file */
    if (secret &&
        !(pwdfile = virTPMWriteSecretToFile(userid,
                                            secret, secret_size)))
         return NULL;

    if (!(storagepath = virTPMCreateCuseTPMStorage(vmuuid, &created, userid)))
        goto error;

    /* create logfile in dir where user creating the state will have access */
    if (!(logfile = virTPMCreateCuseTPMStoragePath(vmuuid, "/vtpm.log")))
        goto error;

    if (created &&
        virTPMSetupCuseTPM(storagepath, vmuuid, userid, logfile, pwdfile,
                           tpm->tpmversion) < 0)
        goto error;

    if (!(devname = virTPMCreateVTPMDeviceName("", vmuuid)) ||
        !(tpm->data.cuse.source.data.file.path =
          virTPMCreateVTPMDeviceName("/dev/", vmuuid)))
        goto error;

    tpm->data.cuse.source.type = VIR_DOMAIN_CHR_TYPE_DEV;

    cmd = virCommandNew(swtpm_cuse);
    if (!cmd)
        goto error;

    virCommandClearCaps(cmd);

    virCommandAddArgFormat(cmd, "-n %s", devname);

    virCommandAddArg(cmd, "--tpmstate");
    virCommandAddArgFormat(cmd, "dir=%s", storagepath);

    virCommandAddArg(cmd, "--log");
    virCommandAddArgFormat(cmd, "file=%s", logfile);

    /* allow process to open logfile by root before dropping privileges */
    virCommandAllowCap(cmd, CAP_DAC_OVERRIDE);

    if (userid && !STREQ(userid, "root")) {
        virCommandAddArgList(cmd, "-r", userid, NULL);
        virCommandAllowCap(cmd, CAP_SETGID);
        virCommandAllowCap(cmd, CAP_SETUID);
    }

    if (pwdfile) {
        virCommandAddArg(cmd, "--key");
        virCommandAddArgFormat(cmd, "pwdfile=%s,remove=true", pwdfile);
    }

    if (pidfile) {
        virCommandAddArg(cmd, "--pid");
        virCommandAddArgFormat(cmd, "file=%s", pidfile);
    }

    switch (tpm->tpmversion) {
    case VIR_DOMAIN_TPM_VERSION_1_2:
        break;
    case VIR_DOMAIN_TPM_VERSION_2:
        virCommandAddArg(cmd, "--tpm2");
        break;
    }

    VIR_FREE(devname);
    tpm->data.cuse.storagepath = storagepath;
    VIR_FREE(tpm->data.cuse.logfile);
    tpm->data.cuse.logfile = logfile;
    VIR_FREE(tpm->data.cuse.pwdfile);
    tpm->data.cuse.pwdfile = pwdfile;

    return cmd;

 error:
    if (pwdfile)
        unlink(pwdfile);
    if (created)
        virTPMDeleteCuseTPMStorage(vmuuid);

    VIR_FREE(tpm->data.cuse.source.data.file.path);
    VIR_FREE(storagepath);
    VIR_FREE(logfile);
    VIR_FREE(devname);
    VIR_FREE(pwdfile);

    virCommandFree(cmd);

    return NULL;
}

/*
 * virTPMStopCuseTPM
 * @tpm: TPM definition
 * @vmuuid: the UUID of the VM
 * @verbose: whether to report errors
 *
 * Gracefully stop the external CUSE TPM
 */
void
virTPMStopCuseTPM(virDomainTPMDefPtr tpm, const unsigned char *vmuuid,
                  bool verbose)
{
    virCommandPtr cmd;
    int exitstatus;
    char *pathname;
    char *errbuf = NULL;

    if (virTPMCuseInit() < 0)
        return;

    if (!(pathname = virTPMCreateVTPMDeviceName("/dev/", vmuuid)))
        return;

    cmd = virCommandNew(swtpm_ioctl);

    virCommandAddArg(cmd, "-s");
    virCommandAddArg(cmd, pathname);

    VIR_FREE(pathname);

    virCommandSetErrorBuffer(cmd, &errbuf);

    if (virCommandRun(cmd, &exitstatus) < 0 || exitstatus != 0) {
        if (verbose)
            VIR_ERROR(_("Could not run swtpm_ioctl -s '%s'."
                      " existstatus: %d\nstderr: %s"),
                      swtpm_ioctl, exitstatus, errbuf);
    }

    virCommandFree(cmd);

    VIR_FREE(tpm->data.cuse.source.data.file.path);
    VIR_FREE(errbuf);
    tpm->data.cuse.source.type = 0;
}
