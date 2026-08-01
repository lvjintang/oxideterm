use anyhow::Context;
use anyhow::Result;
#[cfg(not(target_os = "macos"))]
use keyring::Entry;
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod macos_auth;

#[cfg(target_os = "macos")]
pub use macos_auth::authenticate_device_owner;

/// Stores application secrets in the platform credential manager.
#[derive(Clone, Debug)]
pub struct NativeSecretStore {
    service: String,
}

/// A secret namespace that uses the portable vault when portable mode is
/// enabled, and the OS credential manager otherwise.
#[derive(Clone, Debug)]
pub struct ScopedSecretStore {
    service: String,
}

impl ScopedSecretStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    pub fn store(&self, account: &str, secret: Zeroizing<String>) -> Result<()> {
        if secret.is_empty() {
            return self.delete(account);
        }
        if oxideterm_portable_runtime::is_portable_mode()? {
            return oxideterm_portable_runtime::keystore::store_secret(
                &self.service,
                account,
                secret.as_str(),
            )
            .context("failed to store secret in the portable vault");
        }
        NativeSecretStore::new(&self.service).store(account, secret.as_str())
    }

    pub fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
        if oxideterm_portable_runtime::is_portable_mode()? {
            return match oxideterm_portable_runtime::keystore::get_secret(&self.service, account) {
                Ok(secret) => Ok(Some(secret)),
                Err(oxideterm_portable_runtime::keystore::PortableKeystoreError::NotFound(_)) => {
                    Ok(None)
                }
                Err(error) => Err(error).context("failed to load secret from the portable vault"),
            };
        }
        NativeSecretStore::new(&self.service).get_and_relax(account)
    }

    pub fn exists(&self, account: &str) -> Result<bool> {
        if oxideterm_portable_runtime::is_portable_mode()? {
            return oxideterm_portable_runtime::keystore::secret_exists(&self.service, account)
                .context("failed to inspect secret in the portable vault");
        }
        NativeSecretStore::new(&self.service).exists(account)
    }

    pub fn delete(&self, account: &str) -> Result<()> {
        if oxideterm_portable_runtime::is_portable_mode()? {
            return oxideterm_portable_runtime::keystore::delete_secret(&self.service, account)
                .context("failed to delete secret from the portable vault");
        }
        NativeSecretStore::new(&self.service).delete(account)
    }
}

impl NativeSecretStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    pub fn store(&self, account: &str, secret: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            return macos::store(&self.service, account, secret);
        }

        #[cfg(not(target_os = "macos"))]
        self.entry(account)?
            .set_password(secret)
            .context("failed to store secret in the OS credential manager")
    }

    pub fn get(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
        #[cfg(target_os = "macos")]
        {
            return macos::get(&self.service, account);
        }

        #[cfg(not(target_os = "macos"))]
        match self.entry(account)?.get_password() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => {
                Err(error).context("failed to load secret from the OS credential manager")
            }
        }
    }

    /// Loads a secret and restores the Preview 14 ACL after a successful read.
    pub fn get_and_relax(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
        let secret = self.get(account)?;
        #[cfg(target_os = "macos")]
        if let Some(secret) = secret.as_ref() {
            // Callers use this only after accepting the stored value as a valid
            // domain secret, so invalid config keys take the plain get path.
            self.store(account, secret.as_str())?;
        }
        Ok(secret)
    }

    pub fn delete(&self, account: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            return macos::delete(&self.service, account);
        }

        #[cfg(not(target_os = "macos"))]
        match self.entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => {
                Err(error).context("failed to delete secret from the OS credential manager")
            }
        }
    }

    pub fn exists(&self, account: &str) -> Result<bool> {
        #[cfg(target_os = "macos")]
        {
            return macos::exists(&self.service, account);
        }

        #[cfg(target_os = "windows")]
        {
            let entry = self.entry(account)?;
            if let Some(credential) = entry
                .get_credential()
                .downcast_ref::<keyring::windows::WinCredential>()
            {
                // Windows Credential Manager supports a metadata-only lookup.
                return Ok(credential.get_credential().is_ok());
            }
            return Ok(self.get(account)?.is_some());
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        Ok(self.get(account)?.is_some())
    }

    #[cfg(not(target_os = "macos"))]
    fn entry(&self, account: &str) -> Result<Entry> {
        Entry::new(&self.service, account).context("failed to open an OS credential manager entry")
    }
}
