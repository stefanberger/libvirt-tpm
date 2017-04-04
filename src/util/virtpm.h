/*
 * virtpm.h: TPM support
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
#ifndef __VIR_TPM_H__
# define __VIR_TPM_H__

# include "vircommand.h"

typedef struct _virDomainTPMDef virDomainTPMDef;
typedef virDomainTPMDef *virDomainTPMDefPtr;

char *virTPMCreateCancelPath(const char *devpath) ATTRIBUTE_NOINLINE;

int virTPMEmulatorInitPaths(virDomainTPMDefPtr tpm,
                            const char *swtpmStorageDir,
                            const char *vmname)
                          ATTRIBUTE_RETURN_CHECK;
int virTPMEmulatorPrepareHost(virDomainTPMDefPtr tpm,
                              const char *logDir, const char *vmname,
                              uid_t swtpm_user, const char *swtpmStateDir,
                              uid_t qemu_user)
                          ATTRIBUTE_RETURN_CHECK;
virCommandPtr virTPMEmulatorBuildCommand(virDomainTPMDefPtr tpm,
                                         const char *vmname,
                                         const unsigned char *vmuuid,
                                         uid_t swtpm_user)
                          ATTRIBUTE_RETURN_CHECK;
void virTPMEmulatorStop(const char *swtpmStateDir,
                        const char *vmname);
void virTPMDeleteEmulatorStorage(const char *path);

#endif /* __VIR_TPM_H__ */
