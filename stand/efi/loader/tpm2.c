#include <efi.h>
#include <efilib.h>
#include <efichar.h>


#define EFI_TCG2_PROTOCOL_GUID \
  {0x607f766c, 0x7455, 0x42be, { 0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f }}


static EFI_GUID tcg2_protocol = EFI_TCG2_PROTOCOL_GUID;


EFI_STATUS tpm2_init() {
	EFI_STATUS status;
	EFI_CONSOLE_CONTROL_PROTOCOL *console_control = NULL;
	
	status = BS->LocateProtocol(&tcg2_protocol, NULL,
	    (VOID **)&tcg2);

	if (status != EFI_SUCCESS) {
		ST->ConOut->OutputString(ST->ConOut, (CHAR16 *)L"Failed to locate TCG2 protocol.\r\n");
		BS->Exit(IH, status, 0, NULL);
	}
}
