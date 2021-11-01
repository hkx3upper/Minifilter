#pragma once

#include "filefunc.h"

extern KEVENT g_SynchronizationEvent;

NTSTATUS EptPrivilegeDecrypt(IN PUNICODE_STRING FileName);