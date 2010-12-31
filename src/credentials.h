#ifndef __CREDENTIALS_H
#define __CREDENTIALS_H

#include <windows.h>
#include <wincred.h>
#include "passphrase.h"
#include "options.h"


#define OPENVPN_ERROR_NOT_FOUND ERROR_NOT_FOUND
#define OPENVPN_ERROR_NO_SUCH_LOGON_SESSION ERROR_NO_SUCH_LOGON_SESSION 
#define OPENVPN_ERROR_INVALID_FLAGS  ERROR_INVALID_FLAGS 

DWORD SaveCredentials(int config, struct user_auth user_auth);
DWORD ReadCredentials(int config, struct user_auth *user_auth);


#endif