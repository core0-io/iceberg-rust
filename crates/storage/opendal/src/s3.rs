// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use http::{HeaderName, HeaderValue, Request, Response};
use iceberg::io::{
    CLIENT_REGION, S3_ACCESS_KEY_ID, S3_ALLOW_ANONYMOUS, S3_ASSUME_ROLE_ARN,
    S3_ASSUME_ROLE_EXTERNAL_ID, S3_ASSUME_ROLE_SESSION_NAME, S3_DISABLE_CONFIG_LOAD,
    S3_DISABLE_EC2_METADATA, S3_ENDPOINT, S3_MULTIPART_PART_SIZE_BYTES, S3_PATH_STYLE_ACCESS,
    S3_REGION, S3_REMOTE_SIGNING_ENABLED, S3_SECRET_ACCESS_KEY, S3_SESSION_TOKEN,
    S3_SIGNER_ENDPOINT, S3_SIGNER_URI, S3_SSE_KEY, S3_SSE_MD5, S3_SSE_TYPE,
};
use iceberg::{Error, ErrorKind, Result};
use opendal::raw::new_request_sign_error;
use opendal::services::S3Config;
use opendal::{Buffer, Configurator, HttpBody, HttpTransport, HttpTransporter, Operator};
/// AWS credentials: access key ID, secret access key, and optional session token.
pub use reqsign_aws_v4::Credential as AwsCredential;
/// Trait for types that can asynchronously supply [`AwsCredential`] to a [`CustomAwsCredentialLoader`].
pub use reqsign_core::ProvideCredential;
use reqsign_core::{
    Context, ProvideCredentialChain, ProvideCredentialDyn, SignRequest, Signer, SigningCredential,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::utils::{from_opendal_error, is_truthy};

/// S3 rejects a non-final part smaller than this.
const MULTIPART_PART_SIZE_MIN: u64 = 5 * 1024 * 1024;

/// Java reads this property as an `int`, so a larger value fails there.
const MULTIPART_PART_SIZE_MAX: u64 = i32::MAX as u64;

/// Matches Java `S3FileIOProperties.MULTIPART_SIZE_DEFAULT`.
const MULTIPART_PART_SIZE_DEFAULT: u64 = 32 * 1024 * 1024;

pub(crate) fn default_multipart_part_size() -> u64 {
    MULTIPART_PART_SIZE_DEFAULT
}

/// Parse iceberg props to s3 multipart upload part size.
pub(crate) fn s3_multipart_part_size_parse(m: &HashMap<String, String>) -> Result<u64> {
    let Some(value) = m.get(S3_MULTIPART_PART_SIZE_BYTES) else {
        return Ok(default_multipart_part_size());
    };
    let part_size = value.parse::<u64>().map_err(|e| {
        Error::new(
            ErrorKind::DataInvalid,
            format!("Invalid {S3_MULTIPART_PART_SIZE_BYTES}: {value}: {e}"),
        )
    })?;
    if part_size < MULTIPART_PART_SIZE_MIN {
        return Err(Error::new(
            ErrorKind::DataInvalid,
            format!(
                "Invalid {S3_MULTIPART_PART_SIZE_BYTES}: {part_size} bytes is below the S3 minimum part size of {} MiB",
                MULTIPART_PART_SIZE_MIN / (1024 * 1024)
            ),
        ));
    }
    if part_size > MULTIPART_PART_SIZE_MAX {
        return Err(Error::new(
            ErrorKind::DataInvalid,
            format!(
                "Invalid {S3_MULTIPART_PART_SIZE_BYTES}: {part_size} bytes is above {MULTIPART_PART_SIZE_MAX} bytes, the largest value Java accepts"
            ),
        ));
    }
    Ok(part_size)
}

/// Parse iceberg props to s3 config and, if enabled, remote signing settings.
pub(crate) fn s3_config_parse(
    mut m: HashMap<String, String>,
) -> Result<(S3Config, Option<S3RemoteSigning>)> {
    let mut cfg = S3Config::default();
    // Match Iceberg `S3FileIOProperties.PATH_STYLE_ACCESS_DEFAULT = false`:
    // virtual-host-style addressing is the spec default. opendal's own
    // default is path-style, which disagrees with the Java SDK and breaks
    // S3-compatible stores that only accept virtual-hosted-style URLs.
    // Any explicit `s3.path-style-access` property below overrides this.
    cfg.enable_virtual_host_style = true;
    if let Some(endpoint) = m.remove(S3_ENDPOINT) {
        cfg.endpoint = Some(endpoint);
    };
    if let Some(access_key_id) = m.remove(S3_ACCESS_KEY_ID) {
        cfg.access_key_id = Some(access_key_id);
    };
    if let Some(secret_access_key) = m.remove(S3_SECRET_ACCESS_KEY) {
        cfg.secret_access_key = Some(secret_access_key);
    };
    if let Some(session_token) = m.remove(S3_SESSION_TOKEN) {
        cfg.session_token = Some(session_token);
    };
    if let Some(region) = m.remove(S3_REGION) {
        cfg.region = Some(region);
    };
    if let Some(region) = m.remove(CLIENT_REGION) {
        cfg.region = Some(region);
    };
    if let Some(path_style_access) = m.remove(S3_PATH_STYLE_ACCESS) {
        cfg.enable_virtual_host_style = !is_truthy(path_style_access.to_lowercase().as_str());
    };
    if let Some(arn) = m.remove(S3_ASSUME_ROLE_ARN) {
        cfg.role_arn = Some(arn);
    }
    if let Some(external_id) = m.remove(S3_ASSUME_ROLE_EXTERNAL_ID) {
        cfg.external_id = Some(external_id);
    };
    if let Some(session_name) = m.remove(S3_ASSUME_ROLE_SESSION_NAME) {
        cfg.role_session_name = Some(session_name);
    };
    let s3_sse_key = m.remove(S3_SSE_KEY);
    if let Some(sse_type) = m.remove(S3_SSE_TYPE) {
        match sse_type.to_lowercase().as_str() {
            // No Server Side Encryption
            "none" => {}
            // S3 SSE-S3 encryption (S3 managed keys). https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html
            "s3" => {
                cfg.server_side_encryption = Some("AES256".to_string());
            }
            // S3 SSE KMS, either using default or custom KMS key. https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingKMSEncryption.html
            "kms" => {
                cfg.server_side_encryption = Some("aws:kms".to_string());
                cfg.server_side_encryption_aws_kms_key_id = s3_sse_key;
            }
            // S3 SSE-C, using customer managed keys. https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerSideEncryptionCustomerKeys.html
            "custom" => {
                cfg.server_side_encryption_customer_algorithm = Some("AES256".to_string());
                cfg.server_side_encryption_customer_key = s3_sse_key;
                cfg.server_side_encryption_customer_key_md5 = m.remove(S3_SSE_MD5);
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::DataInvalid,
                    format!(
                        "Invalid {S3_SSE_TYPE}: {sse_type}. Expected one of (custom, kms, s3, none)"
                    ),
                ));
            }
        }
    };

    if let Some(allow_anonymous) = m.remove(S3_ALLOW_ANONYMOUS)
        && is_truthy(allow_anonymous.to_lowercase().as_str())
    {
        cfg.skip_signature = true;
    }
    if let Some(disable_ec2_metadata) = m.remove(S3_DISABLE_EC2_METADATA)
        && is_truthy(disable_ec2_metadata.to_lowercase().as_str())
    {
        cfg.disable_ec2_metadata = true;
    };
    if let Some(disable_config_load) = m.remove(S3_DISABLE_CONFIG_LOAD)
        && is_truthy(disable_config_load.to_lowercase().as_str())
    {
        cfg.disable_config_load = true;
    };

    let remote_signing = s3_remote_signing_parse(&m, &cfg)?;
    Ok((cfg, remote_signing))
}

fn s3_remote_signing_parse(
    m: &HashMap<String, String>,
    cfg: &S3Config,
) -> Result<Option<S3RemoteSigning>> {
    if !m
        .get(S3_REMOTE_SIGNING_ENABLED)
        .is_some_and(|v| is_truthy(v))
    {
        return Ok(None);
    }
    let base_uri = m
        .get(S3_SIGNER_URI)
        .or_else(|| m.get(CATALOG_URI))
        .ok_or_else(|| {
            Error::new(
                ErrorKind::DataInvalid,
                format!("{S3_REMOTE_SIGNING_ENABLED} requires {S3_SIGNER_URI} or {CATALOG_URI}"),
            )
        })?;
    let endpoint = m
        .get(S3_SIGNER_ENDPOINT)
        .map_or(DEFAULT_SIGNER_ENDPOINT, String::as_str);
    Ok(Some(S3RemoteSigning {
        signer_url: format!(
            "{}/{}",
            base_uri.trim_end_matches('/'),
            endpoint.trim_start_matches('/')
        ),
        region: cfg
            .region
            .clone()
            .unwrap_or_else(|| DEFAULT_REGION.to_string()),
        token: m.get(CATALOG_TOKEN).cloned(),
    }))
}

/// Build new opendal operator from give path.
pub(crate) fn s3_config_build(
    cfg: &S3Config,
    customized_credential_load: &Option<CustomAwsCredentialLoader>,
    remote_signing: &Option<S3RemoteSigning>,
    path: &str,
) -> Result<Operator> {
    let url = Url::parse(path)?;
    let bucket = url.host_str().ok_or_else(|| {
        Error::new(
            ErrorKind::DataInvalid,
            format!("Invalid s3 url: {path}, missing bucket"),
        )
    })?;

    let mut builder = cfg
        .clone()
        .into_builder()
        // Set bucket name.
        .bucket(bucket);

    if let Some(remote_signing) = remote_signing {
        let builder = builder.skip_signature().region(&remote_signing.region);
        let op = Operator::new(builder).map_err(from_opendal_error)?;
        let inner = op.context().http_transport().clone();
        let transport = RemoteSigningTransport {
            signer: remote_signing.signer(inner.clone()),
            inner,
        };
        let ctx = op
            .context()
            .with_http_transport(HttpTransporter::new(transport));
        return Ok(op.with_context(ctx));
    }

    if let Some(loader) = customized_credential_load {
        let chain = ProvideCredentialChain::new().push(Arc::clone(&loader.0));
        builder = builder.credential_provider_chain(chain);
    }

    Operator::new(builder).map_err(from_opendal_error)
}

const CATALOG_URI: &str = "uri";
const CATALOG_TOKEN: &str = "token";
const DEFAULT_SIGNER_ENDPOINT: &str = "v1/aws/s3/sign";
const DEFAULT_REGION: &str = "us-east-1";
const X_AMZ_CONTENT_SHA256: &str = "x-amz-content-sha256";

/// Settings for signing S3 requests through an Iceberg REST catalog's remote signing endpoint.
#[derive(Clone, Serialize, Deserialize)]
pub struct S3RemoteSigning {
    signer_url: String,
    region: String,
    token: Option<String>,
}

impl std::fmt::Debug for S3RemoteSigning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3RemoteSigning")
            .field("signer_url", &self.signer_url)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl S3RemoteSigning {
    fn signer(&self, transport: HttpTransporter) -> Signer<SignerToken> {
        let ctx = Context::new().with_http_send(transport);
        Signer::new(
            ctx,
            SignerToken(self.token.clone()),
            RemoteSigner(self.clone()),
        )
    }
}

/// Bearer token sent to the remote signer.
#[derive(Clone)]
struct SignerToken(Option<String>);

impl std::fmt::Debug for SignerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SignerToken")
    }
}

impl SigningCredential for SignerToken {
    fn is_valid(&self) -> bool {
        true
    }
}

impl ProvideCredential for SignerToken {
    type Credential = Self;

    async fn provide_credential(&self, _ctx: &Context) -> reqsign_core::Result<Option<Self>> {
        Ok(Some(self.clone()))
    }
}

#[derive(Serialize)]
struct S3SignRequest<'a> {
    region: &'a str,
    method: &'a str,
    uri: String,
    headers: HashMap<&'a str, Vec<&'a str>>,
}

#[derive(Deserialize)]
struct S3SignResponse {
    uri: String,
    headers: HashMap<String, Vec<String>>,
}

fn invalid_sign_response(e: impl Into<anyhow::Error>) -> reqsign_core::Error {
    reqsign_core::Error::unexpected("invalid S3 sign response").with_source(e)
}

/// Signs S3 requests by delegating to the Iceberg REST `S3SignRequest` endpoint.
#[derive(Debug)]
struct RemoteSigner(S3RemoteSigning);

impl SignRequest for RemoteSigner {
    type Credential = SignerToken;

    async fn sign_request(
        &self,
        ctx: &Context,
        req: &mut http::request::Parts,
        credential: Option<&SignerToken>,
        _expires_in: Option<Duration>,
    ) -> reqsign_core::Result<()> {
        let mut headers: HashMap<&str, Vec<&str>> = HashMap::new();
        for (name, value) in &req.headers {
            let value = value.to_str().map_err(|e| {
                reqsign_core::Error::request_invalid(format!(
                    "header {name} is not valid ASCII and cannot be remotely signed"
                ))
                .with_source(e)
            })?;
            headers.entry(name.as_str()).or_default().push(value);
        }
        let body = S3SignRequest {
            region: &self.0.region,
            method: req.method.as_str(),
            uri: req.uri.to_string(),
            headers,
        };
        let body = serde_json::to_vec(&body).map_err(|e| {
            reqsign_core::Error::unexpected("failed to serialise S3 sign request").with_source(e)
        })?;

        let mut sign_req =
            Request::post(&self.0.signer_url).header(CONTENT_TYPE, "application/json");
        if let Some(token) = credential.and_then(|c| c.0.as_deref()) {
            sign_req = sign_req.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let sign_req = sign_req.body(Bytes::from(body)).map_err(|e| {
            reqsign_core::Error::request_invalid("failed to build S3 sign request").with_source(e)
        })?;

        let resp = ctx.http_send(sign_req).await?;
        if !resp.status().is_success() {
            return Err(reqsign_core::Error::unexpected(format!(
                "remote signer returned {}: {}",
                resp.status(),
                String::from_utf8_lossy(resp.body())
            ))
            .set_retryable(resp.status().is_server_error()));
        }
        let signed: S3SignResponse = serde_json::from_slice(resp.body()).map_err(|e| {
            reqsign_core::Error::unexpected("failed to parse S3 sign response").with_source(e)
        })?;

        // `Signer` commits these edits only if signing succeeds.
        req.uri = signed.uri.parse().map_err(invalid_sign_response)?;
        for (name, values) in signed.headers {
            let name = HeaderName::try_from(name).map_err(invalid_sign_response)?;
            req.headers.remove(&name);
            for value in values {
                let value = HeaderValue::try_from(value).map_err(invalid_sign_response)?;
                req.headers.append(&name, value);
            }
        }
        Ok(())
    }
}

/// Signs every outgoing request with the remote signer before handing it to `inner`.
struct RemoteSigningTransport {
    signer: Signer<SignerToken>,
    inner: HttpTransporter,
}

impl HttpTransport for RemoteSigningTransport {
    async fn fetch(&self, req: Request<Buffer>) -> opendal::Result<Response<HttpBody>> {
        let (mut parts, body) = req.into_parts();
        parts
            .headers
            .entry(X_AMZ_CONTENT_SHA256)
            .or_insert(HeaderValue::from_static("UNSIGNED-PAYLOAD"));
        self.signer
            .sign(&mut parts, None)
            .await
            .map_err(|e| new_request_sign_error(e.into()))?;
        // Let the HTTP client derive the host header from the signed URI.
        parts.headers.remove(HOST);
        self.inner.fetch(Request::from_parts(parts, body)).await
    }
}

/// Custom AWS credential loader.
///
/// Wraps any [`ProvideCredential`] implementation for use with the S3 storage backend.
/// Use [`CustomAwsCredentialLoader::new`] to create one, then pass it to
/// [`OpenDalStorageFactory::S3`](crate::OpenDalStorageFactory).
pub struct CustomAwsCredentialLoader(Arc<dyn ProvideCredentialDyn<Credential = AwsCredential>>);

impl Clone for CustomAwsCredentialLoader {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl std::fmt::Debug for CustomAwsCredentialLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomAwsCredentialLoader")
            .finish_non_exhaustive()
    }
}

impl CustomAwsCredentialLoader {
    /// Create a new custom AWS credential loader from any [`ProvideCredential`] implementation.
    pub fn new(provider: impl ProvideCredential<Credential = AwsCredential> + 'static) -> Self {
        Self(Arc::new(provider) as Arc<dyn ProvideCredentialDyn<Credential = AwsCredential>>)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use http::HeaderValue;
    use iceberg::io::{
        FileIOBuilder, S3_ENDPOINT, S3_MULTIPART_PART_SIZE_BYTES, S3_PATH_STYLE_ACCESS,
        S3_REMOTE_SIGNING_ENABLED,
    };
    use reqsign_core::{Context, SignRequest};

    use super::{
        MULTIPART_PART_SIZE_DEFAULT, MULTIPART_PART_SIZE_MAX, MULTIPART_PART_SIZE_MIN,
        RemoteSigner, Result, S3RemoteSigning, s3_config_parse, s3_multipart_part_size_parse,
    };
    use crate::OpenDalStorageFactory;

    fn parse_with(prop: Option<&str>) -> bool {
        let mut props = HashMap::new();
        if let Some(v) = prop {
            props.insert(S3_PATH_STYLE_ACCESS.to_string(), v.to_string());
        }
        s3_config_parse(props).unwrap().0.enable_virtual_host_style
    }

    #[tokio::test]
    async fn remote_signing_rejects_non_ascii_header_values() {
        let signer = RemoteSigner(S3RemoteSigning {
            signer_url: "http://127.0.0.1:1/v1/aws/s3/sign".to_string(),
            region: "us-east-1".to_string(),
            token: None,
        });
        let (mut parts, _) = http::Request::get("http://bucket/key")
            .header(
                "x-amz-meta-name",
                HeaderValue::from_bytes(b"caf\xc3\xa9").unwrap(),
            )
            .body(())
            .unwrap()
            .into_parts();

        let err = signer
            .sign_request(&Context::new(), &mut parts, None, None)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("x-amz-meta-name"), "{err}");
    }

    #[tokio::test]
    async fn remote_signing_signs_requests_via_signer_endpoint() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();
        let signer = server
            .mock("POST", "/v1/aws/s3/sign")
            .match_header("authorization", "Bearer secret")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "region": "us-east-1",
                "method": "GET",
                "uri": format!("{url}/bucket/key"),
                "headers": { "x-amz-content-sha256": ["UNSIGNED-PAYLOAD"] },
            })))
            .with_body(
                serde_json::json!({
                    "uri": format!("{url}/bucket/key?signed=1"),
                    "headers": { "authorization": ["AWS4-HMAC-SHA256 remote"] },
                })
                .to_string(),
            )
            .expect_at_least(1)
            .create_async()
            .await;
        let object = server
            .mock("GET", "/bucket/key?signed=1")
            .match_header("authorization", "AWS4-HMAC-SHA256 remote")
            .with_body("hello")
            .create_async()
            .await;

        let file_io = FileIOBuilder::new(Arc::new(OpenDalStorageFactory::S3 {
            customized_credential_load: None,
        }))
        .with_props([
            (S3_ENDPOINT, url.as_str()),
            (S3_PATH_STYLE_ACCESS, "true"),
            (S3_REMOTE_SIGNING_ENABLED, "true"),
            ("uri", url.as_str()),
            ("token", "secret"),
        ])
        .build();
        let content = file_io
            .new_input("s3://bucket/key")
            .unwrap()
            .read()
            .await
            .unwrap();

        assert_eq!(content.as_ref(), b"hello");
        signer.assert_async().await;
        object.assert_async().await;
    }

    #[test]
    fn s3_config_parse_path_style_access() {
        // Match Iceberg S3FileIOProperties.PATH_STYLE_ACCESS_DEFAULT = false.
        assert!(parse_with(None));
        assert!(parse_with(Some("false")));
        assert!(!parse_with(Some("true")));
    }

    fn parse_part_size(prop: Option<&str>) -> Result<u64> {
        let mut props = HashMap::new();
        if let Some(v) = prop {
            props.insert(S3_MULTIPART_PART_SIZE_BYTES.to_string(), v.to_string());
        }
        s3_multipart_part_size_parse(&props)
    }

    #[test]
    fn s3_multipart_part_size_parse_defaults_and_overrides() {
        // Match Iceberg S3FileIOProperties.MULTIPART_SIZE_DEFAULT = 32 MiB.
        assert_eq!(MULTIPART_PART_SIZE_DEFAULT, 32 * 1024 * 1024);
        assert_eq!(parse_part_size(None).unwrap(), MULTIPART_PART_SIZE_DEFAULT);
        assert_eq!(parse_part_size(Some("8388608")).unwrap(), 8 * 1024 * 1024);
    }

    #[test]
    fn s3_multipart_part_size_parse_rejects_invalid() {
        // Match Iceberg S3FileIOProperties.MULTIPART_SIZE_MIN = 5 MiB.
        assert_eq!(MULTIPART_PART_SIZE_MIN, 5 * 1024 * 1024);
        assert!(parse_part_size(Some(&MULTIPART_PART_SIZE_MIN.to_string())).is_ok());
        assert!(parse_part_size(Some(&(MULTIPART_PART_SIZE_MIN - 1).to_string())).is_err());
        assert!(parse_part_size(Some(&MULTIPART_PART_SIZE_MAX.to_string())).is_ok());
        assert!(parse_part_size(Some(&(MULTIPART_PART_SIZE_MAX + 1).to_string())).is_err());
        assert!(parse_part_size(Some("not-a-number")).is_err());
    }
}
