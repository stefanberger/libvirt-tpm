/*
 * virtpm.h: TPM support
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
#ifndef __VIR_TPM_H__
# define __VIR_TPM_H__

# include "vircommand.h"

typedef struct _virDomainTPMDef virDomainTPMDef;
typedef virDomainTPMDef *virDomainTPMDefPtr;

char *virTPMCreateCancelPath(const char *devpath) ATTRIBUTE_RETURN_CHECK;
virCommandPtr virTPMCuseTPMBuildCommand(virDomainTPMDefPtr tpm,
                          const unsigned char *vmuuid,
                          const char *userid,
                          const unsigned char *secret,
                          size_t secret_size) ATTRIBUTE_RETURN_CHECK;
void virTPMStopCuseTPM(virDomainTPMDefPtr tpm, const unsigned char *vmuuid,
                       bool verbose);
void virTPMDeleteCuseTPMStorage(const unsigned char *vmuuid);
int virTPMTryConnect(const char *pathname, unsigned long timeout_ms);
int virTPMExistsCuseTPMStorage(const unsigned char *vmuuid);

#endif /* __VIR_TPM_H__ */
