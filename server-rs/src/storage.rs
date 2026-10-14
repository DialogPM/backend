//! Object storage for attachments: MinIO / S3, or memory (tests).

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Mutex;

use async_trait_shim::BoxFuture;
use bytes::Bytes;
use futures_util::Stream;
use s3::creds::Credentials;
use s3::{Bucket, BucketConfiguration, Region};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage: object not found")]
    NotFound,
    /// The reader did not provide exactly the declared size.
    #[error("storage: size mismatch")]
    SizeMismatch,
    /// The reader failed (e.g. the client body exceeded its limit or broke off).
    #[error("storage: reading the upload failed: {0}")]
    Read(std::io::Error),
    #[error("storage: {0}")]
    Backend(String),
}

pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>;

/// Minimal streaming object store.
pub trait Store: Send + Sync {
    /// Stores exactly `size` bytes read from `r` under `key`. If `r` yields fewer bytes,
    /// `SizeMismatch` is returned and nothing is left behind. Bytes beyond `size` are not read.
    fn put<'a>(
        &'a self,
        key: &'a str,
        r: Pin<Box<dyn AsyncRead + Send + 'a>>,
        size: u64,
    ) -> BoxFuture<'a, Result<(), StorageError>>;
    /// Opens the object and returns its content stream and size.
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(ByteStream, u64), StorageError>>;
    /// Removes the object; a missing object is not an error.
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StorageError>>;
}

pub mod async_trait_shim {
    pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
}

/// Uploads up to this size are buffered in memory; larger ones are spooled to a temp file
/// (S3 needs a known, replayable body).
const MEMORY_SPOOL_LIMIT: u64 = 32 << 20;

/// Reads exactly `size` bytes; fewer means SizeMismatch.
async fn read_exact_all(
    r: &mut (dyn AsyncRead + Send + Unpin),
    size: u64,
) -> Result<Vec<u8>, StorageError> {
    let mut buf = Vec::with_capacity(size.min(MEMORY_SPOOL_LIMIT) as usize);
    let mut limited = r.take(size);
    limited
        .read_to_end(&mut buf)
        .await
        .map_err(StorageError::Read)?;
    if buf.len() as u64 != size {
        return Err(StorageError::SizeMismatch);
    }
    Ok(buf)
}

pub struct Minio {
    bucket: Box<Bucket>,
}

impl Minio {
    /// Connects and creates the bucket if needed.
    pub async fn connect(
        endpoint: &str,
        access: &str,
        secret: &str,
        bucket: &str,
        use_ssl: bool,
        region: &str,
    ) -> Result<Minio, String> {
        let scheme = if use_ssl { "https" } else { "http" };
        let region = Region::Custom {
            region: if region.is_empty() {
                "us-east-1".into()
            } else {
                region.into()
            },
            endpoint: format!("{scheme}://{endpoint}"),
        };
        let creds = Credentials::new(Some(access), Some(secret), None, None, None)
            .map_err(|e| e.to_string())?;
        let b = Bucket::new(bucket, region.clone(), creds.clone())
            .map_err(|e| e.to_string())?
            .with_path_style();
        match b.exists().await {
            Ok(true) => {}
            Ok(false) => {
                if let Err(e) = Bucket::create_with_path_style(
                    bucket,
                    region,
                    creds,
                    BucketConfiguration::default(),
                )
                .await
                {
                    // Another instance may have created it concurrently.
                    if !b.exists().await.unwrap_or(false) {
                        return Err(format!("minio make bucket: {e}"));
                    }
                }
            }
            Err(e) => return Err(format!("minio bucket check: {e}")),
        }
        Ok(Minio { bucket: b })
    }
}

impl Store for Minio {
    fn put<'a>(
        &'a self,
        key: &'a str,
        mut r: Pin<Box<dyn AsyncRead + Send + 'a>>,
        size: u64,
    ) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let path = format!("/{key}");
            let result = if size <= MEMORY_SPOOL_LIMIT {
                let buf = read_exact_all(&mut r, size).await?;
                self.bucket
                    .put_object_with_content_type(&path, &buf, "application/octet-stream")
                    .await
                    .map(|resp| resp.status_code())
            } else {
                // Local temp-file failures (e.g. disk full) are storage failures (503), not
                // client read errors.
                let local = |e: std::io::Error| StorageError::Backend(format!("spool upload: {e}"));
                let tmp = tempfile::NamedTempFile::new().map_err(local)?;
                let mut f = tokio::fs::File::from_std(tmp.reopen().map_err(local)?);
                let mut limited = (&mut r).take(size);
                let mut buf = vec![0u8; 64 << 10];
                let mut n: u64 = 0;
                loop {
                    let k = limited.read(&mut buf).await.map_err(StorageError::Read)?;
                    if k == 0 {
                        break;
                    }
                    tokio::io::AsyncWriteExt::write_all(&mut f, &buf[..k]).await.map_err(local)?;
                    n += k as u64;
                }
                tokio::io::AsyncWriteExt::flush(&mut f).await.map_err(local)?;
                if n != size {
                    return Err(StorageError::SizeMismatch);
                }
                let mut f = tokio::fs::File::open(tmp.path()).await.map_err(local)?;
                self.bucket
                    .put_object_stream_with_content_type(&mut f, &path, "application/octet-stream")
                    .await
                    .map(|resp| resp.status_code())
            };
            match result {
                Ok(code) if (200..300).contains(&code) => Ok(()),
                Ok(code) => {
                    let _ = self.bucket.delete_object(&path).await;
                    Err(StorageError::Backend(format!("put object: HTTP {code}")))
                }
                Err(e) => {
                    let _ = self.bucket.delete_object(&path).await;
                    Err(StorageError::Backend(e.to_string()))
                }
            }
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(ByteStream, u64), StorageError>> {
        Box::pin(async move {
            let path = format!("/{key}");
            let size = match self.bucket.head_object(&path).await {
                Ok((head, 200)) => head.content_length.unwrap_or(0).max(0) as u64,
                Ok((_, 404)) => return Err(StorageError::NotFound),
                Ok((_, code)) => {
                    return Err(StorageError::Backend(format!("head object: HTTP {code}")))
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("404") {
                        return Err(StorageError::NotFound);
                    }
                    return Err(StorageError::Backend(msg));
                }
            };
            let resp = self
                .bucket
                .get_object_stream(&path)
                .await
                .map_err(|e| StorageError::Backend(e.to_string()))?;
            if resp.status_code == 404 {
                return Err(StorageError::NotFound);
            }
            use futures_util::StreamExt;
            let stream = resp
                .bytes
                .map(|r| r.map_err(|e| std::io::Error::other(e.to_string())));
            Ok((Box::pin(stream) as ByteStream, size))
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            match self.bucket.delete_object(format!("/{key}")).await {
                Ok(r) if (200..300).contains(&r.status_code()) || r.status_code() == 404 => Ok(()),
                Ok(r) => Err(StorageError::Backend(format!(
                    "delete object: HTTP {}",
                    r.status_code()
                ))),
                Err(e) => Err(StorageError::Backend(e.to_string())),
            }
        })
    }
}

/// In-memory store for tests.
#[derive(Default)]
pub struct Memory {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

impl Store for Memory {
    fn put<'a>(
        &'a self,
        key: &'a str,
        mut r: Pin<Box<dyn AsyncRead + Send + 'a>>,
        size: u64,
    ) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let buf = read_exact_all(&mut r, size).await?;
            self.objects.lock().unwrap().insert(key.to_string(), buf);
            Ok(())
        })
    }
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(ByteStream, u64), StorageError>> {
        Box::pin(async move {
            let b = self
                .objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or(StorageError::NotFound)?;
            let n = b.len() as u64;
            let s = futures_util::stream::once(async move { Ok(Bytes::from(b)) });
            Ok((Box::pin(s) as ByteStream, n))
        })
    }
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            self.objects.lock().unwrap().remove(key);
            Ok(())
        })
    }
}
