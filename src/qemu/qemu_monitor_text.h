/*
 * qemu_monitor_text.h: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
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


#ifndef QEMU_MONITOR_TEXT_H
#define QEMU_MONITOR_TEXT_H

#include "internal.h"

#include "qemu_monitor.h"
#include "hash.h"

int qemuMonitorTextIOProcess(qemuMonitorPtr mon,
                             const char *data,
                             size_t len,
                             qemuMonitorMessagePtr msg);

int qemuMonitorTextStartCPUs(qemuMonitorPtr mon,
                             virConnectPtr conn);
int qemuMonitorTextStopCPUs(qemuMonitorPtr mon);

int qemuMonitorTextSystemPowerdown(qemuMonitorPtr mon);

int qemuMonitorTextGetCPUInfo(qemuMonitorPtr mon,
                              int **pids);
int qemuMonitorTextGetBalloonInfo(qemuMonitorPtr mon,
                                  unsigned long *currmem);
int qemuMonitorTextGetMemoryStats(qemuMonitorPtr mon,
                                  virDomainMemoryStatPtr stats,
                                  unsigned int nr_stats);
int qemuMonitorTextGetBlockStatsInfo(qemuMonitorPtr mon,
                                     const char *devname,
                                     long long *rd_req,
                                     long long *rd_bytes,
                                     long long *wr_req,
                                     long long *wr_bytes,
                                     long long *errs);


int qemuMonitorTextSetVNCPassword(qemuMonitorPtr mon,
                                  const char *password);
int qemuMonitorTextSetBalloon(qemuMonitorPtr mon,
                              unsigned long newmem);

int qemuMonitorTextEjectMedia(qemuMonitorPtr mon,
                              const char *devname);
int qemuMonitorTextChangeMedia(qemuMonitorPtr mon,
                               const char *devname,
                               const char *newmedia,
                               const char *format);


int qemuMonitorTextSaveVirtualMemory(qemuMonitorPtr mon,
                                     unsigned long long offset,
                                     size_t length,
                                     const char *path);
int qemuMonitorTextSavePhysicalMemory(qemuMonitorPtr mon,
                                      unsigned long long offset,
                                      size_t length,
                                      const char *path);

int qemuMonitorTextSetMigrationSpeed(qemuMonitorPtr mon,
                                     unsigned long bandwidth);

int qemuMonitorTextGetMigrationStatus(qemuMonitorPtr mon,
                                      int *status,
                                      unsigned long long *transferred,
                                      unsigned long long *remaining,
                                      unsigned long long *total);

int qemuMonitorTextMigrateToHost(qemuMonitorPtr mon,
                                 int background,
                                 const char *hostname,
                                 int port);

int qemuMonitorTextMigrateToCommand(qemuMonitorPtr mon,
                                    int background,
                                    const char * const *argv,
                                    const char *target);

int qemuMonitorTextMigrateToUnix(qemuMonitorPtr mon,
                                 int background,
                                 const char *unixfile);

int qemuMonitorTextMigrateCancel(qemuMonitorPtr mon);

int qemuMonitorTextAddUSBDisk(qemuMonitorPtr mon,
                              const char *path);

int qemuMonitorTextAddUSBDeviceExact(qemuMonitorPtr mon,
                                     int bus,
                                     int dev);
int qemuMonitorTextAddUSBDeviceMatch(qemuMonitorPtr mon,
                                     int vendor,
                                     int product);


int qemuMonitorTextAddPCIHostDevice(qemuMonitorPtr mon,
                                    virDomainDevicePCIAddress *hostAddr,
                                    virDomainDevicePCIAddress *guestAddr);

int qemuMonitorTextAddPCIDisk(qemuMonitorPtr mon,
                              const char *path,
                              const char *bus,
                              virDomainDevicePCIAddress *guestAddr);

int qemuMonitorTextAddPCINetwork(qemuMonitorPtr mon,
                                 const char *nicstr,
                                 virDomainDevicePCIAddress *guestAddr);

int qemuMonitorTextRemovePCIDevice(qemuMonitorPtr mon,
                                   virDomainDevicePCIAddress *guestAddr);

int qemuMonitorTextSendFileHandle(qemuMonitorPtr mon,
                                  const char *fdname,
                                  int fd);

int qemuMonitorTextCloseFileHandle(qemuMonitorPtr mon,
                                   const char *fdname);

int qemuMonitorTextAddHostNetwork(qemuMonitorPtr mon,
                                  const char *netstr);

int qemuMonitorTextRemoveHostNetwork(qemuMonitorPtr mon,
                                     int vlan,
                                     const char *netname);

int qemuMonitorTextGetPtyPaths(qemuMonitorPtr mon,
                               virHashTablePtr paths);

int qemuMonitorTextAttachPCIDiskController(qemuMonitorPtr mon,
                                           const char *bus,
                                           virDomainDevicePCIAddress *guestAddr);


#endif /* QEMU_MONITOR_TEXT_H */
