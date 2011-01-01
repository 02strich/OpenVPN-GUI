#include "credentials.h"
#include <stdio.h>
#include <tchar.h>

extern struct options o;

DWORD SaveCredentials(int config, struct user_auth user_auth)
{
	CREDENTIAL credentials;
	int pwdlen=-1;
	int usrlen=-1;

	ZeroMemory(&credentials,sizeof(CREDENTIAL));
	
	usrlen=strlen(user_auth.username); //unicode !!!
	pwdlen=strlen(user_auth.password); //Password remains ASCII
	
	
	credentials.TargetName= (PTCHAR) malloc( (_tcslen(o.cnn[config].config_name) + _tcslen(o.credentials_prefix_string)+ 2) * sizeof(TCHAR) );
	_stprintf(credentials.TargetName,TEXT("%s-%s"),o.credentials_prefix_string,o.cnn[config].config_name);

	credentials.UserName = (PTCHAR) malloc( (usrlen+1) * sizeof(TCHAR) );
    _tcsncpy(credentials.UserName, user_auth.username, usrlen+1);

	credentials.CredentialBlob=(LPBYTE)malloc(pwdlen*sizeof(CHAR));
	if(NULL==credentials.CredentialBlob)
		return -1;

	strncpy((PCHAR)credentials.CredentialBlob,user_auth.password,pwdlen);
	// must be the same for unicode and non-unicode enviroments 
	
	//WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,,,,,NULL,NULL);

	credentials.CredentialBlobSize = pwdlen;
	credentials.Comment=TEXT("");
	credentials.Persist = CRED_PERSIST_LOCAL_MACHINE; //preserve accross sessions; CRED_PERSIST_SESSION only for the current session
	credentials.TargetAlias = 0; // If the credential Type is CRED_TYPE_GENERIC, this member can be non-NULL, but the credential manager ignores the member.
	credentials.Type = CRED_TYPE_GENERIC;

	if(TRUE!=CredWrite(&credentials,0))
		return -1;

	free(credentials.TargetName);
	free(credentials.UserName);
	free(credentials.CredentialBlob);

	SecureZeroMemory(&credentials,sizeof(CREDENTIAL));

	return 0;
}

DWORD ReadCredentials(int config, struct user_auth *user_auth)
{
	PCREDENTIAL pcredential;
	PTCHAR buf;
	BOOL ret;

	buf = (PTCHAR) malloc( (_tcslen(o.cnn[config].config_name) + _tcslen(o.credentials_prefix_string) + 2) * sizeof(TCHAR) );
	_stprintf(buf,TEXT("%s-%s"),o.credentials_prefix_string,o.cnn[config].config_name);

	
	if(TRUE != CredRead(buf,CRED_TYPE_GENERIC,0,&pcredential))
	{
		DWORD ret=GetLastError();
		switch(ret)
		{
			case ERROR_NOT_FOUND:
				return OPENVPN_ERROR_NOT_FOUND; //no saved credentials
			case ERROR_NO_SUCH_LOGON_SESSION:
				return OPENVPN_ERROR_NO_SUCH_LOGON_SESSION;
			case ERROR_INVALID_FLAGS:
				return OPENVPN_ERROR_INVALID_FLAGS;
		}

	}
	
#ifdef _UNICODE
	WideCharToMultiByte(CP_UTF8,
		                WC_ERR_INVALID_CHARS,
						(PWCHAR)pcredential->UserName,
		                wcslen((PWCHAR)pcredential->UserName),
		                user_auth->username,
						sizeof(user_auth->username),
						NULL,
						NULL
					   );
#else
	strncpy(user_auth->username,(PCHAR)pcredential->UserName,strlen(pcredential->UserName));
#endif
	strncpy(user_auth->password,(PCHAR)pcredential->CredentialBlob,pcredential->CredentialBlobSize);

	SecureZeroMemory(pcredential->CredentialBlob, pcredential->CredentialBlobSize);
	CredFree(pcredential); //free the buffer

	return 0;
}