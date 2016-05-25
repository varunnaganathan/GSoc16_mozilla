/* This Source Code Form is subject to the terms of the Mozilla Public
+ * License, v. 2.0. If a copy of the MPL was not distributed with this
+ * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/*
+ * Deal with PKCS #11 Slots.
+ */
#include "seccomon.h"
#include "secmod.h"
#include "nssilock.h"
#include "secmodi.h"
#include "secmodti.h"
#include "pkcs11t.h"
#include "pk11func.h"
#include "secitem.h"
#include "secerr.h"

#include "dev.h" 
#include "dev3hack.h" 
#include "pkim.h"
#include "utilpars.h"

/* Prevent p11-kit from including its own pkcs11.h */
#define PKCS11_H 1
#include <p11-kit/uri.h>


char *
PK11_GetTokenUri(PK11SlotInfo *slot)
{
    SECStatus rv;
    P11KitUri *uri;
    char *result;

    uri = p11_kit_uri_new();
    if (!uri) {
	    PORT_SetError(SEC_ERROR_NO_MEMORY);
	    return NULL;
    }
    rv = PK11_GetTokenInfo(slot, p11_kit_uri_get_token_info(uri));
    if (rv == SECFailure) {
	    p11_kit_uri_free(uri);
	    return NULL;
    }
    if (p11_kit_uri_format(uri, P11_KIT_URI_FOR_TOKEN, &result)) {
	    //PORT_SetError(WTF?);
	    result = NULL;
    }
    p11_kit_uri_free(uri);
    return result;
}

//Similar to SECMOD_FindModule
SECMODModule *PK11_FindModuleByUri(char *uri)
{
    P11KitUri *URI = NULL;
    CK_ATTRIBUTE_POINTER library_descripton;
    CK_ATTRIBUTE_POINTER library_manufacturer;
    CK_ATTRIBUTE_POINTER library_version;
    SECMODModuleList *listnode;
    SECMODModule *module = NULL;
    CK_INFO *moduleinfo;
    SECStatus status;
    int st = p11_kit_uri_parse(uri, P11_KIT_URI_FOR_MODULE, URI);
    if (!st)
    {
        //Raise error
    }
    /*Have doubts regarding the CK_ATTRIBUTE_TYPE.passing ints 0 for library-description
    1 for libarry-manufacturer and 2 for library-version */
    library_description = p11_kit_uri_get_attribute(URI, 0);
    library_manufacturer = p11_kit_uri_get_attribute(URI, 1);
    library_version = p11_kit_uri_get_attribute(URI, 2);
    //Ask what this means.Copied because was present in SECMOD_FindModule
    if (!moduleLock) {
        PORT_SetError(SEC_ERROR_NOT_INITIALIZED);
        return module;
    }
    SECMOD_GetReadLock(moduleLock);
    for(listnode =  modules; listnode != NULL; listnode = listnode->next)
    {
        status = PK11_GetModInfo(&listnode->module, moduleinfo);
        //use PORT_Strcmp to compare
        if(moduleinfo->manufacturerID == library_manufacturer && moduleinfo->libraryDescription == libraryDescription && moduleinfo->libraryVersion == libraryVersion)
        {
            module = &listnode->module;
            break;
        }
    }
    SECMOD_ReleaseReadLock(moduleLock);
    if(!module)
    {
        return (SECMODModule *)NULL;
    }
    return module;
}

