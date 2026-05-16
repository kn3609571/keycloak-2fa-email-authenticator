package com.mesutpiskin.keycloak.auth.email;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;

import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EmailAuthenticatorCredentialProviderTest {

    private EmailAuthenticatorCredentialProvider provider;
    private KeycloakSession session;
    private RealmModel realm;
    private UserModel user;
    private SubjectCredentialManager credentialManager;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        realm = mock(RealmModel.class);
        user = mock(UserModel.class);
        credentialManager = mock(SubjectCredentialManager.class);
        when(user.credentialManager()).thenReturn(credentialManager);
        when(realm.getAuthenticationFlowsStream()).thenReturn(Stream.empty());
        provider = new EmailAuthenticatorCredentialProvider(session);
    }

    @Test
    void testIsConfiguredFor_WithStoredCredential() {
        var credential = new EmailAuthenticatorCredentialModel();
        when(credentialManager.getStoredCredentialsByTypeStream(EmailAuthenticatorCredentialModel.TYPE_ID))
                .thenReturn(Stream.of(credential));

        boolean result = provider.isConfiguredFor(realm, user, EmailAuthenticatorCredentialModel.TYPE_ID);

        assertTrue(result, "Should be configured when a stored credential exists");
    }

    @Test
    void testIsConfiguredFor_WithNoStoredCredential_NoSkipSetup() {
        when(credentialManager.getStoredCredentialsByTypeStream(EmailAuthenticatorCredentialModel.TYPE_ID))
                .thenReturn(Stream.empty());

        boolean result = provider.isConfiguredFor(realm, user, EmailAuthenticatorCredentialModel.TYPE_ID);

        assertFalse(result, "Should not be configured when no stored credential and no skip-setup config");
    }

    @Test
    void testIsConfiguredFor_WrongCredentialType() {
        boolean result = provider.isConfiguredFor(realm, user, "wrong-type");

        assertFalse(result, "Should return false for unsupported credential type");
    }

    @Nested
    @DisplayName("Skip-setup fallback for users with email")
    class SkipSetupTests {

        private AuthenticationFlowModel flow;
        private AuthenticationExecutionModel execution;
        private AuthenticatorConfigModel config;

        @BeforeEach
        void setUp() {
            when(credentialManager.getStoredCredentialsByTypeStream(EmailAuthenticatorCredentialModel.TYPE_ID))
                    .thenReturn(Stream.empty());

            flow = mock(AuthenticationFlowModel.class);
            execution = mock(AuthenticationExecutionModel.class);
            config = mock(AuthenticatorConfigModel.class);

            when(flow.getId()).thenReturn("flow-1");
            when(realm.getAuthenticationFlowsStream()).thenReturn(Stream.of(flow));
            when(realm.getAuthenticationExecutionsStream("flow-1")).thenReturn(Stream.of(execution));
            when(execution.getAuthenticator()).thenReturn(EmailAuthenticatorFormFactory.PROVIDER_ID);
            when(execution.getAuthenticatorConfig()).thenReturn("config-1");
            when(realm.getAuthenticatorConfigById("config-1")).thenReturn(config);
        }

        @Test
        @DisplayName("Returns true when skipSetup=true and user has email")
        void testSkipSetup_true_withEmail() {
            when(config.getConfig()).thenReturn(Map.of(EmailConstants.SKIP_SETUP, "true"));
            when(user.getEmail()).thenReturn("user@example.com");

            boolean result = provider.isConfiguredFor(realm, user, EmailAuthenticatorCredentialModel.TYPE_ID);

            assertTrue(result, "Should be configured when skipSetup=true and user has email");
        }

        @Test
        @DisplayName("Returns false when skipSetup=false and no stored credential")
        void testSkipSetup_false_noCredential() {
            when(config.getConfig()).thenReturn(Map.of(EmailConstants.SKIP_SETUP, "false"));
            when(user.getEmail()).thenReturn("user@example.com");

            boolean result = provider.isConfiguredFor(realm, user, EmailAuthenticatorCredentialModel.TYPE_ID);

            assertFalse(result, "Should not be configured when skipSetup=false and no stored credential");
        }

        @Test
        @DisplayName("Returns false when skipSetup=true but user has no email")
        void testSkipSetup_true_noEmail() {
            when(config.getConfig()).thenReturn(Map.of(EmailConstants.SKIP_SETUP, "true"));
            when(user.getEmail()).thenReturn(null);

            boolean result = provider.isConfiguredFor(realm, user, EmailAuthenticatorCredentialModel.TYPE_ID);

            assertFalse(result, "Should not be configured when user has no email even with skipSetup=true");
        }

        @Test
        @DisplayName("Returns false when skipSetup=true but user has blank email")
        void testSkipSetup_true_blankEmail() {
            when(config.getConfig()).thenReturn(Map.of(EmailConstants.SKIP_SETUP, "true"));
            when(user.getEmail()).thenReturn("   ");

            boolean result = provider.isConfiguredFor(realm, user, EmailAuthenticatorCredentialModel.TYPE_ID);

            assertFalse(result, "Should not be configured when user has blank email even with skipSetup=true");
        }

        @Test
        @DisplayName("Returns true when conditional authenticator has skipSetup=true and user has email")
        void testConditionalAuthenticator_skipSetup_true_withEmail() {
            when(execution.getAuthenticator()).thenReturn(ConditionalEmailAuthenticatorFormFactory.PROVIDER_ID);
            when(config.getConfig()).thenReturn(Map.of(EmailConstants.SKIP_SETUP, "true"));
            when(user.getEmail()).thenReturn("user@example.com");

            boolean result = provider.isConfiguredFor(realm, user, EmailAuthenticatorCredentialModel.TYPE_ID);

            assertTrue(result, "Should be configured for conditional authenticator with skipSetup=true and email");
        }

        @Test
        @DisplayName("Returns true with default skipSetup (true) when no config is set")
        void testDefaultSkipSetup_withEmail() {
            when(execution.getAuthenticatorConfig()).thenReturn(null);
            when(user.getEmail()).thenReturn("user@example.com");

            boolean result = provider.isConfiguredFor(realm, user, EmailAuthenticatorCredentialModel.TYPE_ID);

            assertTrue(result, "Should be configured by default (skipSetup defaults to true) when user has email");
        }

        @Test
        @DisplayName("Stored credential takes precedence over skipSetup=false")
        void testStoredCredential_overridesSkipSetupFalse() {
            when(config.getConfig()).thenReturn(Map.of(EmailConstants.SKIP_SETUP, "false"));
            when(user.getEmail()).thenReturn("user@example.com");

            var credential = new EmailAuthenticatorCredentialModel();
            when(credentialManager.getStoredCredentialsByTypeStream(EmailAuthenticatorCredentialModel.TYPE_ID))
                    .thenReturn(Stream.of(credential));

            boolean result = provider.isConfiguredFor(realm, user, EmailAuthenticatorCredentialModel.TYPE_ID);

            assertTrue(result, "Should be configured when stored credential exists, regardless of skipSetup");
        }
    }
}
