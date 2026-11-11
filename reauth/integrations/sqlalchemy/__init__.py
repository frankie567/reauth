"""SQLAlchemy Core storage integrations."""

from reauth.integrations.sqlalchemy.authentication_session import (
    SQLAlchemyAuthenticationSessionService,
    create_authentication_session_table,
)
from reauth.integrations.sqlalchemy.backup_codes import (
    SQLAlchemyBackupCodesFactor,
    create_backup_codes_enrollment_table,
)
from reauth.integrations.sqlalchemy.email_otp import (
    AuthenticationSessionNotFoundException,
    SQLAlchemyEmailOTPFactor,
    create_email_otp_table,
)
from reauth.integrations.sqlalchemy.exceptions import (
    MissingTransactionException,
    ReauthSQLAlchemyException,
)
from reauth.integrations.sqlalchemy.hotp import (
    SQLAlchemyHOTPFactor,
    create_hotp_enrollment_table,
)
from reauth.integrations.sqlalchemy.identity_session import (
    InvalidSessionFamilyException,
    SQLAlchemyIdentitySessionService,
    create_identity_session_table,
)
from reauth.integrations.sqlalchemy.oauth2 import (
    SQLAlchemyAppleOAuth2Factor,
    SQLAlchemyGitHubOAuth2Factor,
    SQLAlchemyGoogleOAuth2Factor,
    SQLAlchemyOAuth2Mixin,
    SQLAlchemyOIDCFactor,
    SQLAlchemyPrivateKeyJWTOIDCFactor,
    create_oauth2_enrollment_table,
)
from reauth.integrations.sqlalchemy.oauth2_state import (
    SQLAlchemyOAuth2StateService,
    create_oauth2_state_table,
)
from reauth.integrations.sqlalchemy.totp import (
    SQLAlchemyTOTPFactor,
    create_totp_enrollment_table,
)

__all__ = [
    "AuthenticationSessionNotFoundException",
    "InvalidSessionFamilyException",
    "MissingTransactionException",
    "ReauthSQLAlchemyException",
    "SQLAlchemyAppleOAuth2Factor",
    "SQLAlchemyAuthenticationSessionService",
    "SQLAlchemyBackupCodesFactor",
    "SQLAlchemyEmailOTPFactor",
    "SQLAlchemyGitHubOAuth2Factor",
    "SQLAlchemyGoogleOAuth2Factor",
    "SQLAlchemyHOTPFactor",
    "SQLAlchemyIdentitySessionService",
    "SQLAlchemyOAuth2Mixin",
    "SQLAlchemyOAuth2StateService",
    "SQLAlchemyOIDCFactor",
    "SQLAlchemyPrivateKeyJWTOIDCFactor",
    "SQLAlchemyTOTPFactor",
    "create_authentication_session_table",
    "create_backup_codes_enrollment_table",
    "create_email_otp_table",
    "create_hotp_enrollment_table",
    "create_identity_session_table",
    "create_oauth2_enrollment_table",
    "create_oauth2_state_table",
    "create_totp_enrollment_table",
]
