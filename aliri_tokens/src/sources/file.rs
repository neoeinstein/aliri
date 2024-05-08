//! A file token source and caching layer

use std::{error, io, path::PathBuf};

use async_trait::async_trait;
use tokio::fs::OpenOptions;

use super::{AsyncTokenCache, AsyncTokenSource};
use crate::TokenWithLifetime;

/// A token source that uses a local file
#[derive(Debug)]
pub struct FileTokenSource {
    path: PathBuf,
}

impl FileTokenSource {
    /// Constructs a new file token source
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    async fn read_token(&mut self) -> Result<TokenWithLifetime, io::Error> {
        use tokio::io::AsyncReadExt;

        let mut file = OpenOptions::new().read(true).open(&self.path).await?;
        let mut data = String::new();
        file.read_to_string(&mut data).await?;
        let token = serde_json::from_str(&data)?;
        Ok(token)
    }

    async fn write_token(&mut self, token: &TokenWithLifetime) -> Result<(), io::Error> {
        use tokio::io::AsyncWriteExt;

        let mut file_opts = OpenOptions::new();

        file_opts.create(true).truncate(true).write(true);

        #[cfg(unix)]
        file_opts.mode(0o600);

        let mut file = file_opts.open(&self.path).await?;
        let data = serde_json::to_string_pretty(&token)?;
        file.write_all(data.as_bytes()).await?;
        Ok(())
    }
}

#[async_trait]
impl AsyncTokenSource for FileTokenSource {
    type Error = io::Error;

    async fn request_token(&mut self) -> Result<TokenWithLifetime, Self::Error> {
        self.read_token().await
    }
}

#[async_trait]
impl AsyncTokenCache for FileTokenSource {
    async fn request_token(
        &mut self,
    ) -> Result<TokenWithLifetime, Box<dyn error::Error + Send + Sync + 'static>> {
        Ok(self.read_token().await?)
    }

    async fn persist_token(
        &mut self,
        token: &TokenWithLifetime,
    ) -> Result<(), Box<dyn error::Error + Send + Sync + 'static>> {
        Ok(self.write_token(token).await?)
    }
}
