/*******************************************************************************
 * Copyright (c) 2011, 2017 Eurotech and/or its affiliates and others
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     Eurotech - initial API and implementation
 *******************************************************************************/
package org.eclipse.kapua.service.authorization.access.shiro;

import org.eclipse.kapua.KapuaEntityNotFoundException;
import org.eclipse.kapua.KapuaException;
import org.eclipse.kapua.commons.model.query.predicate.AttributePredicate;
import org.eclipse.kapua.commons.service.internal.AbstractKapuaService;
import org.eclipse.kapua.commons.util.ArgumentValidator;
import org.eclipse.kapua.locator.KapuaLocator;
import org.eclipse.kapua.locator.KapuaProvider;
import org.eclipse.kapua.model.id.KapuaId;
import org.eclipse.kapua.model.query.KapuaQuery;
import org.eclipse.kapua.service.authorization.AuthorizationService;
import org.eclipse.kapua.service.authorization.access.AccessInfo;
import org.eclipse.kapua.service.authorization.access.AccessPermission;
import org.eclipse.kapua.service.authorization.access.AccessPermissionCreator;
import org.eclipse.kapua.service.authorization.access.AccessPermissionListResult;
import org.eclipse.kapua.service.authorization.access.AccessPermissionQuery;
import org.eclipse.kapua.service.authorization.access.AccessPermissionService;
import org.eclipse.kapua.service.authorization.domain.Domain;
import org.eclipse.kapua.service.authorization.permission.Actions;
import org.eclipse.kapua.service.authorization.permission.Permission;
import org.eclipse.kapua.service.authorization.permission.PermissionFactory;
import org.eclipse.kapua.service.authorization.permission.shiro.PermissionValidator;
import org.eclipse.kapua.service.authorization.shiro.AuthorizationEntityManagerFactory;

/**
 * {@link AccessPermission} service implementation.
 *
 * @since 1.0
 */
@KapuaProvider
public class AccessPermissionServiceImpl extends AbstractKapuaService implements AccessPermissionService {

    private static final Domain ACCESS_INFO_DOMAIN = new AccessInfoDomain();

    public AccessPermissionServiceImpl() {
        super(AuthorizationEntityManagerFactory.getInstance());
    }

    @Override
    public AccessPermission create(AccessPermissionCreator accessPermissionCreator)
            throws KapuaException {
        ArgumentValidator.notNull(accessPermissionCreator, "accessPermissionCreator");
        ArgumentValidator.notNull(accessPermissionCreator.getAccessInfoId(), "accessPermissionCreator.accessInfoId");
        ArgumentValidator.notNull(accessPermissionCreator.getPermission(), "accessPermissionCreator.permission");

        //
        // Check Access
        KapuaLocator locator = KapuaLocator.getInstance();
        AuthorizationService authorizationService = locator.getService(AuthorizationService.class);
        PermissionFactory permissionFactory = locator.getFactory(PermissionFactory.class);
        authorizationService.checkPermission(permissionFactory.newPermission(ACCESS_INFO_DOMAIN, Actions.write, accessPermissionCreator.getScopeId()));

        //
        // If permission are created out of the access permission scope, check that the current user has the permission on the external scopeId.
        Permission permission = accessPermissionCreator.getPermission();
        if (permission.getTargetScopeId() == null || !permission.getTargetScopeId().equals(accessPermissionCreator.getScopeId())) {
            authorizationService.checkPermission(permission);
        }

        PermissionValidator.validatePermission(permission);

        return entityManagerSession.onTransactedInsert(em -> {
            //
            // Check that accessInfo exists
            AccessInfo accessInfo = AccessInfoDAO.find(em, accessPermissionCreator.getAccessInfoId());

            if (accessInfo == null) {
                throw new KapuaEntityNotFoundException(AccessInfo.TYPE, accessPermissionCreator.getAccessInfoId());
            }

            return AccessPermissionDAO.create(em, accessPermissionCreator);
        });
    }

    @Override
    public void delete(KapuaId scopeId, KapuaId accessPermissionId) throws KapuaException {
        ArgumentValidator.notNull(scopeId, "scopeId");
        ArgumentValidator.notNull(accessPermissionId, "accessPermissionId");

        // Check Access
        KapuaLocator locator = KapuaLocator.getInstance();
        AuthorizationService authorizationService = locator.getService(AuthorizationService.class);
        PermissionFactory permissionFactory = locator.getFactory(PermissionFactory.class);
        authorizationService.checkPermission(permissionFactory.newPermission(ACCESS_INFO_DOMAIN, Actions.delete, scopeId));

        entityManagerSession.onTransactedAction(em -> {
            if (AccessPermissionDAO.find(em, accessPermissionId) == null) {
                throw new KapuaEntityNotFoundException(AccessPermission.TYPE, accessPermissionId);
            }

            AccessPermissionDAO.delete(em, accessPermissionId);
        });
    }

    @Override
    public AccessPermission find(KapuaId scopeId, KapuaId accessPermissionId)
            throws KapuaException {
        ArgumentValidator.notNull(scopeId, "scopeId");
        ArgumentValidator.notNull(accessPermissionId, "accessPermissionId");

        //
        // Check Access
        KapuaLocator locator = KapuaLocator.getInstance();
        AuthorizationService authorizationService = locator.getService(AuthorizationService.class);
        PermissionFactory permissionFactory = locator.getFactory(PermissionFactory.class);
        authorizationService.checkPermission(permissionFactory.newPermission(ACCESS_INFO_DOMAIN, Actions.read, scopeId));

        return entityManagerSession.onResult(em -> AccessPermissionDAO.find(em, accessPermissionId));
    }

    @Override
    public AccessPermissionListResult findByAccessInfoId(KapuaId scopeId, KapuaId accessInfoId)
            throws KapuaException {
        ArgumentValidator.notNull(scopeId, "scopeId");
        ArgumentValidator.notNull(accessInfoId, "accessInfoId");

        //
        // Build query
        AccessPermissionQuery query = new AccessPermissionQueryImpl(scopeId);
        query.setPredicate(new AttributePredicate<>(AccessPermissionPredicates.ACCESS_INFO_ID, accessInfoId));

        return query(query);
    }

    @Override
    public AccessPermissionListResult query(KapuaQuery<AccessPermission> query)
            throws KapuaException {
        ArgumentValidator.notNull(query, "query");
        ArgumentValidator.notNull(query.getScopeId(), "query.scopeId");

        //
        // Check Access
        KapuaLocator locator = KapuaLocator.getInstance();
        AuthorizationService authorizationService = locator.getService(AuthorizationService.class);
        PermissionFactory permissionFactory = locator.getFactory(PermissionFactory.class);
        authorizationService.checkPermission(permissionFactory.newPermission(ACCESS_INFO_DOMAIN, Actions.read, query.getScopeId()));

        return entityManagerSession.onResult(em -> AccessPermissionDAO.query(em, query));
    }

    @Override
    public long count(KapuaQuery<AccessPermission> query)
            throws KapuaException {
        ArgumentValidator.notNull(query, "query");
        ArgumentValidator.notNull(query.getScopeId(), "query.scopeId");

        //
        // Check Access
        KapuaLocator locator = KapuaLocator.getInstance();
        AuthorizationService authorizationService = locator.getService(AuthorizationService.class);
        PermissionFactory permissionFactory = locator.getFactory(PermissionFactory.class);
        authorizationService.checkPermission(permissionFactory.newPermission(ACCESS_INFO_DOMAIN, Actions.read, query.getScopeId()));

        return entityManagerSession.onResult(em -> AccessPermissionDAO.count(em, query));
    }
}
