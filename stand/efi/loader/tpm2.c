#include "efitpm2.h"
#include "efitpm2nv.h"

#include <efi.h>
#include <efilib.h>
#include <efichar.h>

#include <Protocol/Tcg2Protocol.h>

static EFI_GUID tcg2_protocol = EFI_TCG2_PROTOCOL_GUID;
static EFI_TCG2_PROTOCOL *tcg2 = NULL;


EFI_STATUS tpm2_init() {
	EFI_STATUS status;
	
	printf("Trying to locate TCG2 protocol...\n");
	status = BS->LocateProtocol(&tcg2_protocol, NULL, (VOID **)&tcg2);

	if (status != EFI_SUCCESS) {
		printf("Failed to locate TCG2 protocol.\n");
		BS->Exit(IH, status, 0, NULL);
	}
	
	printf("Successfully located TCG2 protocol.\n");
	
	printf("NV_INDEX_FIRST: 0x%x\n", NV_INDEX_FIRST);
	printf("NV_INDEX_LAST: 0x%x\n", NV_INDEX_LAST);

	for (int i = 0; i < 3; i++) {
		TPMI_RH_NV_INDEX NvIndex = 0x1000001;
		TPM2B_NV_PUBLIC NvPublic;
		TPM2B_NAME NvName;
		
		status = Tpm2NvReadPublic (NvIndex, &NvPublic, &NvName);
		if (status != EFI_SUCCESS) {
			printf("Failed to read public NV at index 0x%x.\n", NvIndex);
		} else {
			printf("Read name: %.*s\n", NvName.size, NvName.name);
		}

	}
	
	printf("Trying Tpm2StartAuthSession...\n");
	TPM2B_DIGEST NonceCaller = { 16 };
	TPM2B_ENCRYPTED_SECRET Salt = { 0 };
	TPMT_SYM_DEF Symmetric = { TPM_ALG_NULL };
	TPMI_SH_AUTH_SESSION SessionHandle;
	TPM2B_NONCE NonceTPM;
	status = Tpm2StartAuthSession (
		TPM_RH_NULL,	// TpmKey
		TPM_RH_NULL,	// Bind
		&NonceCaller,
		&Salt,
		TPM_SE_POLICY,	// SessionType
		&Symmetric,
		TPM_ALG_SHA256,	//AuthHash
		&SessionHandle,
		&NonceTPM
	);
	printf("status: 0x%lx\n", status);
	printf("SessionHandle: 0x%x\n", SessionHandle);
	printf("NonceTPM.size: %d\n", NonceTPM.size);
	
	printf("Trying Tpm2PolicyPCR...\n");
	TPM2B_DIGEST PcrDigest = { .size = 0 };
	TPML_PCR_SELECTION Pcrs = {
		.count = 1,
		.pcrSelections = {
			{
				.hash = TPM_ALG_SHA256,
				.sizeofSelect = PCR_SELECT_MIN,
				.pcrSelect = { (1 << 0) | (1 << 2) | (1 << 4) | (1 << 7) }
			}
		}
	};
	status = Tpm2PolicyPCR(
		SessionHandle, 	// PolicySession
		&PcrDigest,
		&Pcrs
	);
	printf("status: 0x%lx\n", status);
	
	time_t now;
	time_t then = getsecs();
	do {
		now = getsecs();
	} while (now - then < 10);
	
	return EFI_SUCCESS;
}


EFI_STATUS tpm2_geli_passphrase_from_efivar() {
	const char *name = "KernGeomEliPassphrase";
	char *freeme = NULL;
	UINTN len = 0;
	EFI_STATUS status;
	
	if (efi_freebsd_getenv(name, NULL, &len) == EFI_BUFFER_TOO_SMALL) {
		freeme = malloc(len + 1);
		if (freeme == NULL)
			return (status = EFI_OUT_OF_RESOURCES);
		if (efi_freebsd_getenv(name, freeme, &len) == EFI_SUCCESS) {
			freeme[len] = '\0';
			setenv("kern.geom.eli.passphrase", freeme, 1);
			status = EFI_SUCCESS;
		} else {
			status = EFI_DEVICE_ERROR;
		}
		(void)free(freeme);
	} else {
		status = EFI_NOT_FOUND;
	}
	
	return status;
}
