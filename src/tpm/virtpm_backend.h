/*
 * virtpm_backend.h: TPM backend support
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
#ifndef __VIR_TPM_BACKEND_H__
# define __VIR_TPM_BACKEND_H__

#include "domain_conf.h"

int virTPMSetupEncryption(virConnectPtr conn, virDomainDefPtr def,
                          const char *configDir,
                          unsigned char **secret_value,
                          size_t *secret_value_size);

int virTPMDeleteCreatedSecret(virConnectPtr conn,
                              const unsigned char *vmuuid);

#endif /* __VIR_TPM_BACKEND_H__ */
