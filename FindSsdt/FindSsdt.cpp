#include <iostream>
#include <windows.h>
#include "ntapi.h"

// Thanks to TitanHide for the pattern.
char KiSSSPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };

DWORD_PTR FindOffsetToSSDT(DWORD_PTR krnlBase, PIMAGE_SECTION_HEADER textSect) {
    DWORD_PTR textStartAddr = (DWORD_PTR)(krnlBase + textSect->VirtualAddress);
    DWORD sectionSize = textSect->Misc.VirtualSize;

    ULONG offset = 0;

    for (offset; offset < sectionSize - sizeof(KiSSSPattern); offset++)
    {
        if (!memcmp((PVOID)(textStartAddr + offset), KiSSSPattern, sizeof(KiSSSPattern))) {
            break;
        }
    }

    DWORD_PTR instrAdd = (DWORD_PTR)(textStartAddr + offset + sizeof(KiSSSPattern));
    LONG relativeOffset = *(LONG*)(instrAdd + 3);
    PVOID finalAddress = (PVOID)(instrAdd + relativeOffset + 7);

    return (DWORD_PTR) ((instrAdd + relativeOffset + 7) - krnlBase);

}

RTL_PROCESS_MODULE_INFORMATION GetKernelImageInfo() {

    ULONG infoSize = 0;
    PRTL_PROCESS_MODULES modInfo = (PRTL_PROCESS_MODULES)malloc(infoSize);
    NTSTATUS infoStatus = STATUS_INFO_LENGTH_MISMATCH;

    while (infoStatus == STATUS_INFO_LENGTH_MISMATCH) {
        infoStatus = NtQuerySystemInformation(SystemModuleInformation, modInfo, infoSize, &infoSize);
        modInfo = (PRTL_PROCESS_MODULES)realloc(modInfo, infoSize);

    }
    return modInfo->Modules[0];
}

PIMAGE_SECTION_HEADER GetTextSection(DWORD_PTR ntoskrnlBase) {

    auto dosHdr = (PIMAGE_DOS_HEADER)ntoskrnlBase;
    auto ntHdrs = (PIMAGE_NT_HEADERS)(ntoskrnlBase + dosHdr->e_lfanew);
    auto fileHdr = ntHdrs->FileHeader;

    DWORD numberOfSecs = fileHdr.NumberOfSections;
    PIMAGE_SECTION_HEADER fSecHdr = (PIMAGE_SECTION_HEADER)((DWORD_PTR)ntHdrs + sizeof(IMAGE_NT_HEADERS));

    for (size_t i = 0; i < numberOfSecs; i++)
    {
        if (!strcmp((const char*)fSecHdr->Name, ".text")) {
            return fSecHdr;
        }
        fSecHdr = (PIMAGE_SECTION_HEADER)((DWORD_PTR)fSecHdr + sizeof(IMAGE_SECTION_HEADER));
    }

    return NULL;
}

int main()
{
    DWORD_PTR ntoskrnlBase = (DWORD_PTR)LoadLibraryA("ntoskrnl.exe");
    auto kernelTextSection = GetTextSection(ntoskrnlBase);
    
    auto ssdtOffset = FindOffsetToSSDT(ntoskrnlBase, kernelTextSection);

    auto kernelImageInfo = GetKernelImageInfo();
    auto kernelBase = kernelImageInfo.ImageBase;

    printf("SSDT Address: 0x%p\n", (PVOID)((DWORD_PTR)kernelBase + ssdtOffset));
}
