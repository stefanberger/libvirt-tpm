/*
 * tpm_backend.c: internal tpm driver backend contract
 *
 * Copyright (C) 2007-2014 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 * Author: Stefan Berger <stefanb@linux.vnet.ibm.com>
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "datatypes.h"
#include "viralloc.h"
#include "domain_conf.h"
#include "secret_conf.h"
#include "viruuid.h"
#include "virfile.h"
#include "virstring.h"
#include "virtpm_backend.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
virTPMGenerateSecretUUID(virConnectPtr conn,
                         unsigned char *uuid)
{
    unsigned attempt;

    for (attempt = 0; attempt < 65536; attempt++) {
        virSecretPtr tmp;
        if (virUUIDGenerate(uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unable to generate uuid"));
            return -1;
        }
        tmp = conn->secretDriver->secretLookupByUUID(conn, uuid);
        if (tmp == NULL)
            return 0;

        virSecretFree(tmp);
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("too many conflicts when generating a uuid"));

    return -1;
}

static int
virTPMGeneratePassphrase(unsigned char *dest, size_t num_bytes)
{
    int fd;
    size_t i;

    /* A qcow passphrase is up to 16 bytes, with any data following a NUL
       ignored.  Prohibit control and non-ASCII characters to avoid possible
       unpleasant surprises with the qemu monitor input mechanism. */
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot open /dev/urandom"));
        return -1;
    }
    i = 0;
    while (i < num_bytes) {
        ssize_t r;

        while ((r = read(fd, dest + i, 1)) == -1 && errno == EINTR)
            ;
        if (r <= 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot read from /dev/urandom"));
            VIR_FORCE_CLOSE(fd);
            return -1;
        }
        if (dest[i] >= 0x20 && dest[i] <= 0x7E)
            i++; /* Got an acceptable character */
    }
    VIR_FORCE_CLOSE(fd);
    return 0;
}

static int
virTPMSecretCreateUsage(char **dest, const unsigned char *vmuuid)
{
    char uuid[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(vmuuid, uuid);
    return virAsprintf(dest, "vtpm-%s", uuid);
}

int
virTPMDeleteCreatedSecret(virConnectPtr conn,
                          const unsigned char *vmuuid)
{
    virSecretPtr secret = NULL;
    char *usage;

    if (conn->secretDriver == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("secret driver not supported"));
        return -1;
    }

    if (conn->secretDriver->secretLookupByUsage == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("secret lookup not supported"));
        return -1;
    }

    if (conn->secretDriver->secretUndefine == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("secret undefining not supported"));
        return -1;
    }

    if (virTPMSecretCreateUsage(&usage, vmuuid) < 0)
        return -1;

    secret = conn->secretDriver->secretLookupByUsage(conn,
                     VIR_SECRET_USAGE_TYPE_VTPM,
                     usage);

    if (secret)
        conn->secretDriver->secretUndefine(secret);

    VIR_FREE(usage);
    virObjectUnref(secret);

    return 0;
}

static int
virTPMGenerateEncryption(virConnectPtr conn,
                         virDomainTPMDefPtr tpm,
                         const unsigned char *vmuuid)
{
    virSecretDefPtr def = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virStorageEncryptionPtr enc;
    virStorageEncryptionSecretPtr enc_secret = NULL;
    virSecretPtr secret = NULL;
    char *xml;
    unsigned char value[VIR_STORAGE_CUSE_TPM_PASSPHRASE_SIZE];
    int ret = -1;

    if (conn->secretDriver == NULL ||
        conn->secretDriver->secretLookupByUUID == NULL ||
        conn->secretDriver->secretDefineXML == NULL ||
        conn->secretDriver->secretSetValue == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("secret storage not supported"));
        goto cleanup;
    }

    enc = tpm->data.cuse.encryption;
    if (enc->nsecrets != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("secrets already defined"));
        goto cleanup;
    }

    if (VIR_ALLOC(enc_secret) < 0 || VIR_REALLOC_N(enc->secrets, 1) < 0 ||
        VIR_ALLOC(def) < 0)
        goto cleanup;

    def->ephemeral = false;
    def->private = false; //true;
    if (virTPMGenerateSecretUUID(conn, def->uuid) < 0)
        goto cleanup;

    def->usage_type = VIR_SECRET_USAGE_TYPE_VTPM;
    if (virTPMSecretCreateUsage(&def->usage.vtpm, vmuuid) < 0)
        goto cleanup;
    xml = virSecretDefFormat(def);
    virSecretDefFree(def);
    def = NULL;
    if (xml == NULL)
        goto cleanup;

    secret = conn->secretDriver->secretDefineXML(conn, xml, 0);
    VIR_FREE(xml);
    if (secret == NULL)
        goto cleanup;

    if (virTPMGeneratePassphrase(value, sizeof(value)) < 0)
        goto cleanup;

    if (conn->secretDriver->secretSetValue(secret, value, sizeof(value), 0) < 0)
        goto cleanup;

    enc_secret->type = VIR_STORAGE_ENCRYPTION_SECRET_TYPE_PASSPHRASE;
    memcpy(enc_secret->uuid, secret->uuid, VIR_UUID_BUFLEN);
    enc->format = VIR_STORAGE_ENCRYPTION_FORMAT_VTPM;
    enc->secrets[0] = enc_secret; /* Space for secrets[0] allocated above */
    enc_secret = NULL;
    enc->nsecrets = 1;

    ret = 0;

 cleanup:
    if (secret != NULL) {
        if (ret != 0 &&
            conn->secretDriver->secretUndefine != NULL)
            conn->secretDriver->secretUndefine(secret);
        virSecretFree(secret);
    }
    virBufferFreeAndReset(&buf);
    virSecretDefFree(def);
    VIR_FREE(enc_secret);
    return ret;
}

static int
virTPMReuseEncryption(virConnectPtr conn,
                      virDomainTPMDefPtr tpm,
                      const unsigned char *vmuuid)
{
    char *usage;
    virStorageEncryptionSecretPtr enc_secret = NULL;
    virStorageEncryptionPtr enc;
    virSecretPtr secret = NULL;
    int ret = -1;

    if (conn->secretDriver == NULL ||
        conn->secretDriver->secretLookupByUsage == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("secret lookup not supported"));
        goto cleanup;
    }

    enc = tpm->data.cuse.encryption;

    if (virTPMSecretCreateUsage(&usage, vmuuid) < 0)
        goto cleanup;

    secret = conn->secretDriver->secretLookupByUsage(conn,
                     VIR_SECRET_USAGE_TYPE_VTPM,
                     usage);
    if (secret) {
        if (VIR_ALLOC(enc_secret) < 0 || VIR_REALLOC_N(enc->secrets, 1) < 0)
            goto cleanup;
        enc_secret->type = VIR_STORAGE_ENCRYPTION_SECRET_TYPE_PASSPHRASE;
        memcpy(enc_secret->uuid, secret->uuid, VIR_UUID_BUFLEN);
        enc->format = VIR_STORAGE_ENCRYPTION_FORMAT_VTPM;
        enc->secrets[0] = enc_secret; /* Space for secrets[0] allocated above */
        enc_secret = NULL;
        enc->nsecrets = 1;
    }

    ret = 0;

cleanup:
    VIR_FREE(usage);
    VIR_FREE(enc_secret);
    virObjectUnref(secret);

    return ret;
}

int
virTPMSetupEncryption(virConnectPtr conn, virDomainDefPtr def,
                      const char *configDir,
                      unsigned char **secret_value, size_t *secret_value_size)
{
    int ret = 0;
    virStorageEncryptionPtr enc = NULL;
    virDomainTPMDefPtr tpm;
    virSecretPtr secret = NULL;
    int i;

    /*
     * in some case def may be NULL; in this case a VM won't be
     * started and we won't do anything here
     */
    if (def == NULL)
        return 0;

    tpm = def->tpm;

    switch (tpm->type) {
    case VIR_DOMAIN_TPM_TYPE_PASSTHROUGH:
        break;
    case VIR_DOMAIN_TPM_TYPE_CUSE_TPM:
        enc = tpm->data.cuse.encryption;
        break;
    case VIR_DOMAIN_TPM_TYPE_LAST:
        break;
    }

    if (enc) {
        if (enc->format == VIR_STORAGE_ENCRYPTION_FORMAT_VTPM &&
            enc->nsecrets > 0) {
            /*
             * during migration we need to create a new secret
             * on the fly
             */
            secret = virSecretLookupByUUID(conn, enc->secrets[0]->uuid);

            if (!secret) {
                for (i = 0; i < enc->nsecrets; i++)
                    VIR_FREE(enc->secrets[i]);
                VIR_FREE(enc->secrets);
                enc->nsecrets = 0;
                enc->format = VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT;
            } else {
                virObjectUnref(secret);
                secret = NULL;
            }
        }
    }

    if (enc) {
        if (enc->format == VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT ||
            enc->nsecrets == 0) {
            /* lookup a left-over secret and reuse it */
            if (virTPMReuseEncryption(conn, tpm, def->uuid) < 0)
                return -1;
            ret = virDomainSaveConfig(configDir, def);
            if (ret < 0)
                goto error;
        }
    }

    if (enc) {
        if (enc->format == VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT ||
            enc->nsecrets == 0) {
            if (virTPMGenerateEncryption(conn, tpm, def->uuid) < 0)
                return -1;
            ret = virDomainSaveConfig(configDir, def);
            if (ret < 0)
                goto error;
        }

        secret = virSecretLookupByUUID(conn, enc->secrets[0]->uuid);

        if (!secret) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not find vTPM secret"));
            goto error;
        }
        *secret_value = conn->secretDriver->secretGetValue(secret,
                                                           secret_value_size, 0,
                                                           VIR_SECRET_GET_VALUE_INTERNAL_CALL);
        if (*secret_value == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not get secret value"));
            ret = -1;
        }
    }

 error:
    virObjectUnref(secret);

    return ret;
}
