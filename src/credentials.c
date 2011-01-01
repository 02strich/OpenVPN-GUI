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
	
	usrlen=_tcslen(user_auth.username); //unicode !!!
	pwdlen=_tcslen(user_auth.password); //unicode !!!
	
	
	credentials.TargetName= (PTCHAR) malloc( (_tcslen(o.cnn[config].config_name) + _tcslen(o.credentials_prefix_string)+ 2) * sizeof(TCHAR) );
	_stprintf(credentials.TargetName,TEXT("%s-%s"),o.credentials_prefix_string,o.cnn[config].config_name);

	credentials.UserName = (PTCHAR) malloc( (usrlen+1) * sizeof(TCHAR) );
	_tcsncpy(credentials.UserName, user_auth.username, usrlen+1);

	credentials.CredentialBlob=(LPBYTE)malloc(pwdlen*sizeof(TCHAR));
	if(NULL==credentials.CredentialBlob)
		return -1;
	
	_tcsncpy((PTCHAR)credentials.CredentialBlob,user_auth.password,pwdlen);

	credentials.CredentialBlobSize=pwdlen;
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
	//MessageBox(NULL,buf,"1",MB_OK);
#pragma message("check for valid data")
	strncpy(user_auth->username,(PTCHAR)pcredential->UserName,_tcslen(pcredential->UserName));
	strncpy(user_auth->password,(PTCHAR)pcredential->CredentialBlob,pcredential->CredentialBlobSize);
	//MessageBox(NULL,"Read","2",MB_OK);
	SecureZeroMemory(pcredential->CredentialBlob, pcredential->CredentialBlobSize);
	//MessageBox(NULL,"Read","3",MB_OK);
	CredFree(pcredential); //free the buffer
	//MessageBox(NULL,"Read","4",MB_OK);
	return 0;
}
