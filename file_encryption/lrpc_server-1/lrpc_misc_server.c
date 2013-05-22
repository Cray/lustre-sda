#include "lrpc_misc_server.h"
#include "KeyGenerator.h"
#define DBG_LEVEL 5
extern FileKeyGenerator *keyGen;

/*Serialize the data*/
/*initial mount serialize EA*/
	bool_t
xdr_extattrKeydata (XDR *xdrs, extattrKeydata *objp)
{
	register int32_t *buf;

	if (!gssrpc_xdr_string (xdrs, &objp->filekey, 2048))
		return FALSE;
	if (!gssrpc_xdr_string (xdrs, &objp->blob, 2048))
		return FALSE;
	if (!gssrpc_xdr_string (xdrs, &objp->blobsign, 2048))
		return FALSE;
	if (!gssrpc_xdr_int (xdrs, &objp->lrpc_ret_code))
                return FALSE;
	return TRUE;
}

	bool_t
xdr_fileID (XDR *xdrs, fileID *objp)
{
	register int32_t *buf;

	if (!gssrpc_xdr_string (xdrs, &objp->fileid, 2048))
		return FALSE;
	return TRUE;
}

	bool_t
xdr_createData (XDR *xdrs, createData *objp)
{
	register int32_t *buf;

	if (!gssrpc_xdr_string (xdrs, &objp->fileid, 2048))
		return FALSE;
	if (!gssrpc_xdr_string (xdrs, &objp->aclid, 2048))
		return FALSE;
	return TRUE;
}

	bool_t
xdr_accessData (XDR *xdrs, accessData *objp)
{
	register int32_t *buf;

	if (!gssrpc_xdr_string (xdrs, &objp->fileid, 2048))
		return FALSE;
	if (!gssrpc_xdr_string (xdrs, &objp->blob, 2048))
		return FALSE;
	if (!gssrpc_xdr_string (xdrs, &objp->blobsign, 2048))
		return FALSE;
	return TRUE;
}


	bool_t
xdr_encKey (XDR *xdrs, encKey *objp)
{
	register int32_t *buf;

	if (!gssrpc_xdr_string (xdrs, &objp->enckey, 2048))
		return FALSE;
	if (!gssrpc_xdr_int (xdrs, &objp->lrpc_ret_code))
                return FALSE;

	return TRUE;
}


bool chk_ciphertext_null_byte(const char * _cipher_text, int _size)
{
	for(int i = 0; i < _size; ++i)
	{
		if(_cipher_text[i] == '\0') {
			return true;
		}
	}
	return false;	
}

char *get_userdata(const char *tgt_usr)
{
	char delims[] = "@";
	char *usr_data = NULL;
	usr_data = strtok( tgt_usr, delims );
	return usr_data;
}


/*Receive new file request
 *create new filekey encrypt using ACL
 *send back the blob
 */
	extattrKeydata *
lrpc_create_svc(createData *cd, const char *tgt_usr, struct svc_req *rqstp)
{

	FILE *dbgstream = stderr;
	int  debug_level = DBG_LEVEL;

	ldapData *ld = NULL;
	extattrKeydata *ea = NULL;
	bool acl_grant = false;
	char *_tgt_usr = NULL;
	_tgt_usr = get_userdata(tgt_usr);
	
	LRPC_LOG(LOG_INFO, "Creating new file key.");
	LRPC_LOG(LOG_INFO, "Received request for File ID::%s and ACL id ::%s", cd->fileid,cd->aclid);
	LRPC_LOG(LOG_INFO, "Validating ACL :: %s", cd->aclid);
	LRPC_LOG(LOG_INFO, "Accessing user %s AD database", _tgt_usr);

	LRPC_ALLOC(ld, ldapData, 1);
	LRPC_ALLOC(ld->aclid, char, BUFSIZ);
	LRPC_ALLOC(ld->tgtuser, char, BUFSIZ);

	strcpy(ld->aclid, cd->aclid);
	strcpy(ld->tgtuser, _tgt_usr);	

	ldap_get_extattr(REQUEST_ACCESS, ld, acl_grant);

	if(acl_grant == false) 
	{
		LRPC_LOG(LOG_ERR, "ACL id :: %s User :: %s access denied",ld->aclid, ld->tgtuser);	
		LRPC_FREE(ld->aclid);
        	LRPC_FREE(ld->tgtuser);
		LRPC_ALLOC(ea, extattrKeydata, 1);
		LRPC_ALLOC(ea->filekey, char, 1);
		LRPC_ALLOC(ea->blob, char, 1);
		LRPC_ALLOC(ea->blobsign, char, 1);
		memset(ea->filekey, 0 ,sizeof(char *));
		memset(ea->blob, 0 ,sizeof(char *));
		memset(ea->blobsign, 0 ,sizeof(char *));
		ea->lrpc_ret_code = LRPC_ACL_VERIFY_ERR;
		return ea;
	}

	/*serialization key*/
	CipherKey aclkey = get_aclkey();
	
	CipherKey cmnkey =  keyGen->createKey(SERIALIZE);
	CipherKey signkey = keyGen->createKey(cd->fileid);
	
	LRPC_LOG(LOG_INFO, "Session TGT user :: %s ",tgt_usr);
	//done with it
	LRPC_FREE(ld->aclid);
	LRPC_FREE(ld->tgtuser);

REGENERATE_KEY:
	LRPC_ALLOC(ea, extattrKeydata, 1);
	CipherKey rckey  =  keyGen->createRandomKey();

	if (!rckey || !aclkey || !cmnkey || !signkey)
		{
			LRPC_LOG(LOG_ERR, "Failed to generate encryption based keys::0x%x",LRPC_KEY_GEN_ERR);
               		LRPC_ALLOC(ea->filekey, char, 1);
                	LRPC_ALLOC(ea->blob, char, 1);
                	LRPC_ALLOC(ea->blobsign, char, 1);
                	memset(ea->filekey, 0 ,sizeof(char *));
                	memset(ea->blob, 0 ,sizeof(char *));
                	memset(ea->blobsign, 0 ,sizeof(char *));
                	ea->lrpc_ret_code = LRPC_KEY_GEN_ERR;
			return (ea);
		}

	keyGen->encodeKey( cmnkey, rckey, &ea->filekey);
	keyGen->encodeKey( aclkey, rckey, &ea->blob);
	//TODO FIXME !!!!! yet to add the aclid to blob
	//sign it using cipherkey from fileid
	keyGen->sign(signkey, (unsigned char *)ea->blob, &ea->blobsign);

	if( chk_ciphertext_null_byte(ea->filekey, keyGen->encodedKeySize()) ||
			chk_ciphertext_null_byte(ea->blob, keyGen->encodedKeySize())    ||
			chk_ciphertext_null_byte(ea->blobsign, keyGen->reEncodedKeySize()) )
	{
		LRPC_LOG(LOG_INFO,"\n***Regenerating new key***\n");
		LRPC_FREE(ea->filekey);
		LRPC_FREE(ea->blob);
		LRPC_FREE(ea->blobsign);
		LRPC_FREE(ea);
		//try to regenerate if NULL bytes found
		goto REGENERATE_KEY;
	}
	
	ea->lrpc_ret_code = LRPC_REPLY_SUCCESS;	
	return(ea);
}


/*Verify the blob recieved.Rehash the blob.
 *Decypher the recieved blobsign.Compare both blob hash.
 */

	encKey *
lrpc_access_svc(accessData *ad, struct svc_req *rqstp)
{

	FILE *dbgstream = stderr;
	int  debug_level = DBG_LEVEL;

	int buf_size;
	char *aclKey;
	encKey *ckey;
	ldapData *ld = NULL;

	LRPC_ALLOC(ld, ldapData, 1);
	LRPC_ALLOC(ld->aclid, char, BUFSIZ);
	LRPC_ALLOC(ld->tgtuser, char, BUFSIZ);

	//FIXME get the user from ticket!!
	strcpy(ld->aclid, "ACL0");
	strcpy(ld->tgtuser, "u0");

	LRPC_ALLOC(ckey,encKey, 1);
	//LRPC_ALLOC(ckey->enckey,char,BLOB_SIZE);
	LRPC_ALLOC(aclKey,char,FILEKEYSIZE);
	XDR rpcxdr;
	char *xdr_buff;
	LRPC_LOG( LOG_INFO, "Verifying the blob.");
	CipherKey verifykey =   keyGen->createKey(ad->fileid);

	bool b  = keyGen->verify(verifykey,(unsigned char *)ad->blobsign,(unsigned char *)ad->blob);

	if(b)
	{
		LRPC_LOG(LOG_INFO,"Blob Sign Verified.");
	}
	else
	{
		LRPC_LOG(LOG_WARN,"Blob Sign verification failed.");
		exit (0);
	}

	//TODO FIXME ACL ID is static!!!!
	CipherKey aclkey = get_aclkey();
	if(!aclkey) 
	{
	LRPC_LOG(LOG_WARN,"ACL key access failed");
	LRPC_FREE(ld->aclid);
        LRPC_FREE(ld->tgtuser);
	LRPC_ALLOC(ckey->enckey,char,1);
        memset(ckey->enckey, 0 ,sizeof(char *));
	ckey->lrpc_ret_code = LRPC_KEY_ACCESS_ERR;
	return ckey;	
	
	}
	CipherKey dckey = keyGen->decodeKey(aclkey,(unsigned char *)ad->blob);
	keyGen->encodeKey( keyGen->createKey(SERIALIZE), dckey , &ckey->enckey);

	LRPC_FREE(ld->aclid);
	LRPC_FREE(ld->tgtuser);

	return ckey;
}

void  processGroupServerKey()
{
	FILE *dbgstream = stderr;
	int  debug_level = DBG_LEVEL;

	char default_group_server_key[] = "Default_GroupServer";
	const char  *group_server_key = "default";
	char *groupServerKey;
	// Step 1. Get GroupServerKey 
	bool found = false;
	groupServerKey = ldap_access_groupserverkey(found, default_group_server_key);
	LRPC_LOG( LOG_INFO,"Group Server Key found:%d",found ) ;
	CipherKey cmnkey =  keyGen->createKey(SERIALIZE);
	CipherKey grpkey =  keyGen->createKey(group_server_key);

	// Step 2. If GroupServerKey not set Create it
	if(! found)
	{
		char **tempGrpKey = malloc(sizeof(char*));
		keyGen->encodeKey( cmnkey, grpkey, tempGrpKey);
		groupServerKey = (char*)malloc(strlen(tempGrpKey[0])+1);
		strcpy(groupServerKey,tempGrpKey[0]);
		ldap_store_groupserverkey(default_group_server_key,groupServerKey);
		LRPC_LOG( LOG_ERR, "Group Server Key updated") ;
		free(tempGrpKey[0]);
		free(tempGrpKey);
	}
}

void processAclKey()
{

	FILE *dbgstream = stderr;
	int  debug_level = DBG_LEVEL;

	char default_acl[] = "ACL0";
	char *encoded_aclkey;
	// Step 1. Get default aclKey 
	bool found = false;
	encoded_aclkey = ldap_access_aclkey(found, default_acl);
	LRPC_LOG( LOG_INFO, "Default acl entry found:%d",found ) ;
	//CipherKey cmnkey =  keyGen->createKey(SERIALIZE);
	CipherKey aclkey =  keyGen->createRandomKey();
	CipherKey groupServerKey = get_groupServerKey();

	// Step 2. If default aclKey not set Create it
	if(! found)
	{
		char **tempAclKey = malloc(sizeof(char*));
		keyGen->encodeKey( groupServerKey, aclkey, tempAclKey);
		encoded_aclkey = (char*)malloc(strlen(tempAclKey[0])+1);
		strcpy(encoded_aclkey,tempAclKey[0]);
		ldap_store_aclkey(default_acl, encoded_aclkey);
		LRPC_LOG( LOG_ERR, "added default acl Key\n" ) ;
		free(tempAclKey[0]);
		free(tempAclKey);
	}
}


CipherKey get_aclkey()
{
	
	FILE *dbgstream = stderr;
	int  debug_level = DBG_LEVEL;
	CipherKey groupServerKey;
	CipherKey retkey;
	char default_acl[] = "ACL0";
	char *encoded_aclkey;
	// Step 1. Get default aclKey 
	bool found = false;
	int attempt = 0;
	reconnect:
	encoded_aclkey = ldap_access_aclkey(found, default_acl);
	
	if(found)
	{	
		groupServerKey = get_groupServerKey();
		retkey  = keyGen->decodeKey(groupServerKey, encoded_aclkey);
		return retkey;
	}
	else
	{
		attempt ++ ;
		LRPC_LOG(LOG_ERR,"Trying to reconnect:%d\n",attempt);
		if(attempt < 3)
		goto reconnect;
 		LRPC_LOG( LOG_ERR," could not find acl key \n");
		return retkey;
	}
}


CipherKey get_groupServerKey()
{
	FILE *dbgstream = stderr;
	int  debug_level = DBG_LEVEL;
	CipherKey cmnkey;
	CipherKey retkey;

	char default_group_server_key[] = "Default_GroupServer";
	char *groupServerKey;
	// Step 1. Get GroupServerKey 
	bool found = false;
	int attempt = 0;
        reconnect:
	groupServerKey = ldap_access_groupserverkey(found, default_group_server_key);
	if(found)
	{
		cmnkey =  keyGen->createKey(SERIALIZE);
		retkey  = keyGen->decodeKey(cmnkey, groupServerKey);
		return retkey;
	}	
	else
	{
		attempt ++ ;
                LRPC_LOG(LOG_ERR,"Trying to reconnect:%d\n",attempt);
                if(attempt < 3)
                goto reconnect;
		LRPC_LOG( LOG_ERR," could not find group server key \n");
		return retkey;
	}
}
