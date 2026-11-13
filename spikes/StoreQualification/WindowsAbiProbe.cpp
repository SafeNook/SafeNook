// Compile as x64 with Windows SDK 10.0.26100.0; no runtime filesystem mutation.
#include <windows.h>
#include <winternl.h>
#include <cstddef>
#include <cstdio>
static_assert(sizeof(void*) == 8);
static_assert(sizeof(UNICODE_STRING) == 16 && offsetof(UNICODE_STRING, Buffer) == 8);
static_assert(sizeof(OBJECT_ATTRIBUTES) == 48 && offsetof(OBJECT_ATTRIBUTES, RootDirectory) == 8);
static_assert(offsetof(OBJECT_ATTRIBUTES, ObjectName) == 16 && offsetof(OBJECT_ATTRIBUTES, Attributes) == 24);
static_assert(offsetof(OBJECT_ATTRIBUTES, SecurityDescriptor) == 32 && offsetof(OBJECT_ATTRIBUTES, SecurityQualityOfService) == 40);
static_assert(sizeof(IO_STATUS_BLOCK) == 16 && offsetof(IO_STATUS_BLOCK, Information) == 8);
static_assert(sizeof(BY_HANDLE_FILE_INFORMATION) == 52);
static_assert(offsetof(BY_HANDLE_FILE_INFORMATION, ftCreationTime) == 4 && offsetof(BY_HANDLE_FILE_INFORMATION, nFileIndexLow) == 48);
static_assert(sizeof(OVERLAPPED) == 32 && offsetof(OVERLAPPED, hEvent) == 24);
// SDK Win32 structure has the same documented field sequence as WDK FILE_RENAME_INFORMATION.
// This checks that sequence; it does not substitute for a WDK-header compilation.
static_assert(sizeof(FILE_RENAME_INFO) == 24 && offsetof(FILE_RENAME_INFO, RootDirectory) == 8);
static_assert(offsetof(FILE_RENAME_INFO, FileNameLength) == 16 && offsetof(FILE_RENAME_INFO, FileName) == 20);
int main() { std::puts("PASS: Windows SDK x64 ABI static assertions (16/48/16/52/32/24)"); }
