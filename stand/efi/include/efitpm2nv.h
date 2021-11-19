#ifndef _EFITPM2NV_H_
#define _EFITPM2NV_H_

#include <efi.h>
#include <IndustryStandard/Tpm20.h>

EFI_STATUS Tpm2NvReadPublic (
	TPMI_RH_NV_INDEX NvIndex,
	TPM2B_NV_PUBLIC *NvPublic,
	TPM2B_NAME *NvName);

#endif

