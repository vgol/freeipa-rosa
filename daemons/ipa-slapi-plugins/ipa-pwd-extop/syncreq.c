/** BEGIN COPYRIGHT BLOCK
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GPLv3 section 7:
 *
 * In the following paragraph, "GPL" means the GNU General Public
 * License, version 3 or any later version, and "Non-GPL Code" means
 * code that is governed neither by the GPL nor a license
 * compatible with the GPL.
 *
 * You may link the code of this Program with Non-GPL Code and convey
 * linked combinations including the two, provided that such Non-GPL
 * Code only links to the code of this Program through those well
 * defined interfaces identified in the file named EXCEPTION found in
 * the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline
 * functions from the Approved Interfaces without causing the resulting
 * work to be covered by the GPL. Only the copyright holders of this
 * Program may make changes or additions to the list of Approved
 * Interfaces.
 *
 * Authors:
 * Nathaniel McCallum <npmccallum@redhat.com>
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include "../libotp/otp_token.h"
#include "syncreq.h"

bool sync_request_present(Slapi_PBlock *pb)
{
    LDAPControl **controls = NULL;

    if (slapi_pblock_get(pb, SLAPI_REQCONTROLS, &controls) != 0)
        return false;

    return ldap_control_find(OTP_SYNC_REQUEST_OID, controls, NULL) != NULL;
}

bool sync_request_handle(const struct otp_config *cfg, Slapi_PBlock *pb,
                         const char *user_dn)
{
    struct otp_token **tokens = NULL;
    LDAPControl **controls = NULL;
    struct berval *second = NULL;
    struct berval *first = NULL;
    BerElement *ber = NULL;
    char *token_dn = NULL;
    bool success;

    if (slapi_pblock_get(pb, SLAPI_REQCONTROLS, &controls) != 0)
        return false;

    if (controls == NULL || controls[0] == NULL)
        return false;

    for (int i = 0; controls[i] != NULL; i++) {
        if (strcmp(controls[i]->ldctl_oid, OTP_SYNC_REQUEST_OID) != 0)
            continue;

        /* Decode the request. */
        ber = ber_init(&controls[i]->ldctl_value);
        if (ber == NULL)
            return false;

        /* Decode the token codes. */
        if (ber_scanf(ber, "{OO", &first, &second) == LBER_ERROR) {
            ber_free(ber, 1);
            return false;
        }

        /* Decode the optional token DN. */
        (void)ber_scanf(ber, "a", &token_dn);

        /* Process the synchronization. */
        success = false;
        if (ber_scanf(ber, "}") != LBER_ERROR) {
            tokens = otp_token_find(cfg, user_dn, token_dn, true, NULL);
            if (tokens != NULL) {
                success = otp_token_validate_berval(tokens, first, second);
                otp_token_free_array(tokens);
            }
        }

        ber_memfree(token_dn); token_dn = NULL;
        ber_bvfree(second);
        ber_bvfree(first);
        ber_free(ber, 1);
        if (!success)
            return false;
    }

    return true;
}
