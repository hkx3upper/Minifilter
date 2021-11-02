#pragma once

#include "filefunc.h"

extern KEVENT g_SynchronizationEvent;

NTSTATUS EptPrivilegeEnDecrypt(IN PUNICODE_STRING FileName, IN LONG OperType);