#ifndef _EFITPM2_H_
#define _EFITPM2_H_

#include <efi.h>

EFI_STATUS tpm2_init();
EFI_STATUS tpm2_geli_passphrase_from_efivar();

#endif

