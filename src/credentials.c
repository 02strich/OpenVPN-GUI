#include "credentials.h"
#include <stdio.h>

DWORD SaveCredentials(const char *targetname, const char *credentials_prefix, struct user_auth user_auth)
{
	CREDENTIAL credentials;
	int pwdlen=-1;
	int usrlen=-1;
	char *buf;
	ZeroMemory(&credentials,sizeof(CREDENTIAL));
	
	usrlen=strlen(user_auth.username);
	pwdlen=strlen(user_auth.password);
	
	
	credentials.TargetName=(LPSTR) malloc(strlen(targetname) + strlen(credentials_prefix)+ 2);



	sprintf(credentials.TargetName,"%s-%s",credentials_prefix,targetname);

	credentials.UserName=(LPSTR)malloc(usrlen+1);
	strncpy(credentials.UserName,user_auth.username,usrlen+1);

	credentials.CredentialBlob=(LPBYTE)malloc(pwdlen);
	if(NULL==credentials.CredentialBlob)
		return -1;
	
	strncpy((char*)credentials.CredentialBlob,user_auth.password,pwdlen);

	credentials.CredentialBlobSize=pwdlen;
	credentials.Comment="";
	credentials.Persist = CRED_PERSIST_LOCAL_MACHINE; //preserve accross sessions; CRED_PERSIST_SESSION only for the current session
	credentials.TargetAlias = 0; // If the credential Type is CRED_TYPE_GENERIC, this member can be non-NULL, but the credential manager ignores the member.
	credentials.Type = CRED_TYPE_GENERIC;


	if(TRUE!=CredWrite(&credentials,0))
		MessageBox(NULL,"Fehler","CredWrite",IDOK);
	return 0;

}

DWORD ReadCredentials(LPTSTR targetname, struct user_auth *user_auth)
{
	PCREDENTIAL pcredential;
	char *buf;
	//MessageBox(NULL,targetname,"",IDOK);

	buf=(char*)malloc(strlen(targetname)+strlen(CRED_PREFIX)+2);
	sprintf(buf,"%s-%s",CRED_PREFIX,targetname);


	if(TRUE!=CredRead(buf,CRED_TYPE_GENERIC,0,&pcredential))
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

	strncpy(user_auth->username,pcredential->UserName,strlen(pcredential->UserName));
	strncpy(user_auth->password,pcredential->CredentialBlob,pcredential->CredentialBlobSize);

	SecureZeroMemory(pcredential->CredentialBlob, pcredential->CredentialBlobSize);

	CredFree(pcredential); //free the buffer
	return 0;
}
