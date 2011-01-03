#include "credentials.h"
#include <stdio.h>
#include <tchar.h>

extern struct options o;

DWORD SaveCredentials(int config, struct user_auth user_auth)
{
	CREDENTIALA credentials;
	int pwdlen=-1;
	int usrlen=-1;

	ZeroMemory(&credentials,sizeof(CREDENTIALA));
	
	usrlen=strlen(user_auth.username); //unicode !!!
	pwdlen=strlen(user_auth.password); //Password Unicode because Windows UI saved Unicode in W7
	
	
	credentials.TargetName= (char*) malloc( (strlen(o.cnn[config].config_name) + strlen(o.credentials_prefix_string)+ 2) * sizeof(char) );
	sprintf(credentials.TargetName,"%s-%s",o.credentials_prefix_string,o.cnn[config].config_name);

	credentials.UserName = (char*) malloc( (usrlen+1) * sizeof(char));
    strncpy(credentials.UserName, user_auth.username, usrlen+1);
	/* Password has to be UNICODE to be compatible with Windows UI changes */
	credentials.CredentialBlob=(LPBYTE)malloc(pwdlen*sizeof(WCHAR));
	if(NULL==credentials.CredentialBlob)
		return -1;

	credentials.CredentialBlobSize = pwdlen * sizeof(WCHAR);
#pragma message("Error Handling")
	MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,user_auth.password,strlen(user_auth.password),(PWCHAR)credentials.CredentialBlob,credentials.CredentialBlobSize);
	//strncpy((PCHAR)credentials.CredentialBlob,user_auth.password,pwdlen);
	// must be the same for unicode and non-unicode enviroments 
	
	//WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,,,,,NULL,NULL);

	credentials.Comment="";
	credentials.Persist = CRED_PERSIST_ENTERPRISE; //preserve accross sessions; CRED_PERSIST_SESSION only for the current session
	credentials.TargetAlias = 0; // If the credential Type is CRED_TYPE_GENERIC, this member can be non-NULL, but the credential manager ignores the member.
	credentials.Type = CRED_TYPE_GENERIC;

	if(TRUE!=CredWriteA(&credentials,0))
		return -1;

	free(credentials.TargetName);
	free(credentials.UserName);
	free(credentials.CredentialBlob);

	SecureZeroMemory(&credentials,sizeof(CREDENTIALA));

	return 0;
}


DWORD ReadCredentials(int config, struct user_auth *user_auth)
{
	PCREDENTIALA pcredential;
	char *buf;
	BOOL ret;

	buf = (char*) malloc( (strlen(o.cnn[config].config_name) + strlen(o.credentials_prefix_string) + 2) * sizeof(char) );
	sprintf(buf,"%s-%s",o.credentials_prefix_string,o.cnn[config].config_name);

	
	if(TRUE != CredReadA(buf,CRED_TYPE_GENERIC,0,&pcredential))
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
	
	strncpy(user_auth->username,(PCHAR)pcredential->UserName,strlen(pcredential->UserName));
	
    /* Password is always UNICODE, to be compatibl with Windows UI */ 
	WideCharToMultiByte(CP_UTF8,
		                WC_ERR_INVALID_CHARS,
						(PWCHAR)pcredential->CredentialBlob,
						pcredential->CredentialBlobSize/sizeof(WCHAR),
						user_auth->password,
						sizeof(user_auth->password),
						NULL,
						NULL
					   );
	
	SecureZeroMemory(pcredential->CredentialBlob, pcredential->CredentialBlobSize);
	CredFree(pcredential); //free the buffer

	return 0;
}