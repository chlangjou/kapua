/*******************************************************************************
 * Copyright (c) 2017 Eurotech and/or its affiliates and others
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Eurotech - initial API and implementation
 *******************************************************************************/
package org.eclipse.kapua.broker.core.plugin.authentication;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.kapua.KapuaException;
import org.eclipse.kapua.broker.core.plugin.Acl;
import org.eclipse.kapua.broker.core.plugin.KapuaConnectionContext;

public class AdminAuthenticationLogic extends AuthenticationLogic {

    public AdminAuthenticationLogic(String addressPrefix, String addressClassifier, String advisoryPrefix) {
        super(addressPrefix, addressClassifier, advisoryPrefix);
    }

    @Override
    public List<AuthorizationEntry> connect(KapuaConnectionContext kcc, AuthenticationCallback authenticationCallback) throws KapuaException {
        return buildAuthorizationMap(kcc);
    }

    @Override
    public void disconnect(KapuaConnectionContext kcc, AuthenticationCallback authenticationCallback, Throwable error) {
    }

    protected List<AuthorizationEntry> buildAuthorizationMap(KapuaConnectionContext kcc) {
        ArrayList<AuthorizationEntry> ael = new ArrayList<AuthorizationEntry>();
        ael.add(createAuthorizationEntry(kcc, Acl.ALL, aclHash));
        ael.add(createAuthorizationEntry(kcc, Acl.WRITE_ADMIN, aclAdvisory));
        kcc.logAuthDestinationToLog();
        return ael;
    }

}
