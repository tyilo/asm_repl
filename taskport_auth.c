#include <Security/Authorization.h>

#include "taskport_auth.h"

bool taskport_auth(void) {
	OSStatus stat;
	AuthorizationItem taskport_item[] = {{"system.privilege.taskport:"}};
	AuthorizationRights rights = {1, taskport_item}, *out_rights = NULL;
	AuthorizationRef author;

	AuthorizationFlags auth_flags = kAuthorizationFlagExtendRights | kAuthorizationFlagPreAuthorize | kAuthorizationFlagInteractionAllowed | (1 << 5);

	stat = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, auth_flags, &author);
	if(stat != errAuthorizationSuccess) {
		return false;
	}

	stat = AuthorizationCopyRights(author, &rights, kAuthorizationEmptyEnvironment, auth_flags, &out_rights);
	if(stat != errAuthorizationSuccess) {
		return false;
	}
	return true;
}
