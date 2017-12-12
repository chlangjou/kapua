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

import org.eclipse.kapua.broker.core.plugin.KapuaConnectionContext;

public interface AuthenticationCallback {

    /**
     * Return a connection id if the device is alredy connected. Null otherwise
     * 
     * @return
     */
    String getConnectionId(KapuaConnectionContext kcc);
}
