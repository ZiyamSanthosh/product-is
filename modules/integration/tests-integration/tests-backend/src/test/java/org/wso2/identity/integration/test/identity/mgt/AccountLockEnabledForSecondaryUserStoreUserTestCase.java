/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.integration.test.identity.mgt;

import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang.ArrayUtils;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.automation.engine.annotations.ExecutionEnvironment;
import org.wso2.carbon.automation.engine.annotations.SetEnvironment;
import org.wso2.carbon.identity.governance.stub.bean.Property;
import org.wso2.carbon.identity.user.store.configuration.stub.dto.UserStoreDTO;
import org.wso2.carbon.integration.common.admin.client.AuthenticatorClient;
import org.wso2.carbon.um.ws.api.stub.ClaimValue;
import org.wso2.identity.integration.common.clients.ResourceAdminServiceClient;
import org.wso2.identity.integration.common.clients.UserManagementClient;
import org.wso2.identity.integration.common.clients.mgt.IdentityGovernanceServiceClient;
import org.wso2.identity.integration.common.clients.user.store.config.UserStoreConfigAdminServiceClient;
import org.wso2.identity.integration.common.clients.user.store.count.UserStoreCountServiceClient;
import org.wso2.identity.integration.common.clients.usermgt.remote.RemoteUserStoreManagerServiceClient;
import org.wso2.identity.integration.common.utils.ISIntegrationTest;
import org.wso2.identity.integration.common.utils.UserStoreConfigUtils;

public class AccountLockEnabledForSecondaryUserStoreUserTestCase extends ISIntegrationTest {

    private String newUserName = "WSO2TEST.COM/userStoreUser";
    private String newUserNameWithoutDomainName = "WSO2TEST.COM/userStoreUser";
    private String newUserRole = "WSO2TEST.COM/jdsbUserStoreRole";
    private String  newUserPassword = "password";
    private String wrongPassword = "wrongPassword";
    private final String domainId = "WSO2TEST.COM";
    private final String jdbcClass = "org.wso2.carbon.user.core.jdbc.UniqueIDJDBCUserStoreManager";
    private final String rwLDAPClass = "org.wso2.carbon.user.core.ldap.UniqueIDReadWriteLDAPUserStoreManager";
    private final String roLDAPClass = "org.wso2.carbon.user.core.ldap.UniqueIDReadOnlyLDAPUserStoreManager";
    private final String adLDAPClass = "org.wso2.carbon.user.core.ldap.UniqueIDActiveDirectoryUserStoreManager";
    private static final String USER_STORE_DB_NAME = "JDBC_USER_STORE_ADDING_DB";
    private static final String PERMISSION_LOGIN = "/permission/admin/login";
    private UserStoreConfigUtils userStoreConfigUtils =  new UserStoreConfigUtils();
    private UserManagementClient userMgtClient;
    private AuthenticatorClient authenticatorClient;
    private UserStoreConfigAdminServiceClient userStoreConfigAdminServiceClient;
    private UserStoreCountServiceClient userStoreCountServiceClient;
    private IdentityGovernanceServiceClient identityGovernanceServiceClient;
    private ResourceAdminServiceClient resourceAdminServiceClient;
    private RemoteUserStoreManagerServiceClient usmClient;

    private static final String ENABLE_ACCOUNT_LOCK = "account.lock.handler.lock.on.max.failed.attempts.enable";
    private static final String TRUE_STRING = "true";
    private static final String DEFAULT = "default";
    private String accountLockClaimUri = "http://wso2.org/claims/identity/accountLocked";

    @BeforeClass(alwaysRun = true)
    public void init() throws Exception {
        super.init();
        authenticatorClient = new AuthenticatorClient(backendURL);
        enableAccountLocking(ENABLE_ACCOUNT_LOCK);
        userStoreConfigAdminServiceClient = new UserStoreConfigAdminServiceClient(backendURL, sessionCookie);
        userStoreCountServiceClient = new UserStoreCountServiceClient(backendURL, sessionCookie);
        usmClient = new RemoteUserStoreManagerServiceClient(backendURL, sessionCookie);
        resourceAdminServiceClient = new ResourceAdminServiceClient(backendURL, sessionCookie);
    }

    @AfterClass(alwaysRun = true)
    public void atEnd() throws Exception {
        userStoreConfigAdminServiceClient.deleteUserStore(domainId);
        disableAccountLocking(ENABLE_ACCOUNT_LOCK);
    }

    @Test(groups = "wso2.is", description = "Check user store manager implementations")
    public void testAvailableUserStoreClasses() throws Exception {
        String[] classes = userStoreConfigAdminServiceClient.getAvailableUserStoreClasses();
        List<String> classNames = Arrays.asList(classes);
        Assert.assertTrue(classNames.contains(jdbcClass), jdbcClass + " not present in User Store List.");
        Assert.assertTrue(classNames.contains(rwLDAPClass), rwLDAPClass + " not present.");
        Assert.assertTrue(classNames.contains(roLDAPClass), roLDAPClass + " not present.");
        Assert.assertTrue(classNames.contains(adLDAPClass), adLDAPClass + " not present.");

    }

    @Test(groups = "wso2.is", description = "Check add user store via DTO",
            dependsOnMethods = "testAvailableUserStoreClasses")
    private void testAddJDBCUserStore() throws Exception {

        UserStoreDTO userStoreDTO = userStoreConfigAdminServiceClient.createUserStoreDTO(jdbcClass, domainId,
                userStoreConfigUtils.getJDBCUserStoreProperties(USER_STORE_DB_NAME));
        userStoreConfigAdminServiceClient.addUserStore(userStoreDTO);
        Thread.sleep(5000);
        Assert.assertTrue(userStoreConfigUtils.waitForUserStoreDeployment(userStoreConfigAdminServiceClient, domainId)
                , "Domain addition via DTO has failed.");

    }

    @Test(groups = "wso2.is", dependsOnMethods = "testAddJDBCUserStore")
    public void addUserIntoJDBCUserStore() throws Exception {
        userMgtClient = new UserManagementClient(backendURL, getSessionCookie());

        userMgtClient.addRole(newUserRole, null, new String[]{PERMISSION_LOGIN});
        Assert.assertTrue(userMgtClient.roleNameExists(newUserRole)
                , "Role name doesn't exists");

        userMgtClient.addUser(newUserName, newUserPassword, new String[]{newUserRole}, null);
        Assert.assertTrue(userMgtClient.userNameExists(newUserRole, newUserName), "User name doesn't exists");

        String sessionCookie = authenticatorClient.login(newUserName, newUserPassword, isServer
                .getInstance().getHosts().get("default"));
        Assert.assertTrue(sessionCookie.contains("JSESSIONID"), "Session Cookie not found. Login failed");
        authenticatorClient.logOut();
    }

    // @SetEnvironment(executionEnvironments = {ExecutionEnvironment.ALL})
    @Test(groups = "wso2.is", description = "Check whether the secondary user store user account lock successfully",
            dependsOnMethods = "addUserIntoJDBCUserStore")
    public void testSuccessfulSecondaryUserStoreUserAccountLock() {
        try {
            // usmClient.addUser(testLockUser1, testLockUser1Password, new String[]{"admin"}, new ClaimValue[0], null, false);

            int maximumAllowedFailedLogins = 5;
            for (int i = 0; i < maximumAllowedFailedLogins; i++) {
                try {
                    authenticatorClient.login(newUserName, wrongPassword,
                            isServer.getInstance().getHosts().get("default"));
                } catch (Exception e) {
                    log.error("Login attempt: " + i + " for user: " + newUserName + " failed");
                }
            }

            ClaimValue[] claimValues = usmClient.getUserClaimValuesForClaims(newUserName, new String[]
                    {accountLockClaimUri}, "default");

            String userAccountLockClaimValue = null;

            if (ArrayUtils.isNotEmpty(claimValues)) {
                userAccountLockClaimValue = claimValues[0].getValue();
            }

            junit.framework.Assert.assertTrue
                    ("Test Failure : User Account Didn't Locked Properly", Boolean.valueOf(userAccountLockClaimValue));

        } catch (Exception e) {
            log.error("Error occurred when locking the test user.", e);
        }
    }

    protected void enableAccountLocking(String option) throws Exception {
        identityGovernanceServiceClient = new IdentityGovernanceServiceClient(sessionCookie, backendURL);

        Thread.sleep(5000);
        authenticatorClient.login(isServer.getSuperTenant().getTenantAdmin().getUserName(),
                isServer.getSuperTenant().getTenantAdmin().getPassword(),
                isServer.getInstance().getHosts().get(DEFAULT));

        Property[] newProperties = new Property[1];
        Property prop = new Property();
        prop.setName(option);
        prop.setValue(TRUE_STRING);
        newProperties[0] = prop;
        identityGovernanceServiceClient.updateConfigurations(newProperties);
    }

    protected void disableAccountLocking(String option) throws Exception {

        Property[] newProperties = new Property[1];
        Property prop = new Property();
        prop.setName(option);
        prop.setValue("false");
        newProperties[0] = prop;
        identityGovernanceServiceClient.updateConfigurations(newProperties);
    }

}
