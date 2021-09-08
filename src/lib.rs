mod credentials;
mod error;
mod shell;

use anyhow::Context;
use anyhow::Result;
use credentials::*;
use error::CliError;
use shell::Shell;
use google_authenticator::GoogleAuthenticator;

use rusoto_core::request::HttpClient;
use rusoto_core::{Client, Region};
use rusoto_credential::ProfileProvider;
use rusoto_iam::{GetUserRequest, Iam, IamClient, ListMFADevicesRequest, ListMFADevicesResponse};
use rusoto_sts::{AssumeRoleRequest, GetCallerIdentityRequest, GetSessionTokenRequest, Sts, StsClient, Credentials};
use std::collections::HashMap;
use std::env;
use std::process::Command;
use structopt::clap::AppSettings;
use structopt::StructOpt;

#[cfg(not(target_os = "windows"))]
const DEFAULT_SHELL: &str = "/bin/sh";

#[cfg(target_os = "windows")]
const DEFAULT_SHELL: &str = "cmd.exe";

const AWS_PROFILE: &str = "AWS_PROFILE";
const AWS_DEFAULT_REGION: &str = "AWS_DEFAULT_REGION";

#[derive(StructOpt, Debug, Clone)]
#[structopt(
    name = "aws-mfa-session",
        global_settings(&[AppSettings::ColoredHelp, AppSettings::NeedsLongHelp, AppSettings::NeedsSubcommandHelp]),
)]
pub struct Args {
    /// AWS credential profile to use. AWS_PROFILE is used by default
    #[structopt(long = "profile", short = "p")]
    profile: Option<String>,
    /// AWS credentials file location to use. AWS_SHARED_CREDENTIALS_FILE is used if not defined
    #[structopt(long = "credentials-file", short = "f")]
    file: Option<String>,
    /// AWS region. AWS_REGION is used if not defined
    #[structopt(long = "region", short = "r")]
    region: Option<Region>,
    /// MFA code from MFA resource
    #[structopt(long = "code", short = "c")]
    code: Option<String>,
    /// MFA secret
    #[structopt(long = "secret")]
    secret: Option<String>,    
    /// MFA device ARN from user profile. It could be detected automatically
    #[structopt(long = "arn", short = "a")]
    arn: Option<String>,
    /// Role ARN to assume
    #[structopt(long = "rolearn")]
    rolearn: Option<String>,
    /// Run shell with AWS credentials as environment variables
    #[structopt(short = "s")]
    shell: bool,
    /// Print(export) AWS credentials as environment variables
    #[structopt(short = "e")]
    export: bool,
    /// Update AWS credential profile with temporary session credentials
    #[structopt(long = "update-profile", short = "u")]
    session_profile: Option<String>,
}

pub async fn run(opts: Args) -> Result<(), CliError> {
    // ProfileProvider is limited, but AWS_PROFILE is used elsewhere
    if let Some(profile) = opts.profile {
        env::set_var(AWS_PROFILE, profile);
    }

    if let Some(file) = opts.file {
        env::set_var(AWS_SHARED_CREDENTIALS_FILE, file);
    }

    let provider = ProfileProvider::new()?;
    let dispatcher = HttpClient::new()?;
    let client = Client::new_with(provider, dispatcher);

    let region: Region = match opts.region {
        Some(region) => region,
        None => match std::env::var(AWS_DEFAULT_REGION) {
            Ok(s) => s.parse::<Region>()?,
            _ => Default::default(),
        },
    };

    let iam_client = IamClient::new_with_client(client.clone(), region.clone());

    let serial_number = match opts.arn {
        None => {
            // get mfa-device
            let mfa_request = ListMFADevicesRequest {
                marker: None,
                max_items: Some(1),
                user_name: None,
            };
            let response = iam_client.list_mfa_devices(mfa_request).await?;
            let ListMFADevicesResponse { mfa_devices, .. } = response;
            let serial = &mfa_devices.get(0).ok_or(CliError::NoMFA)?.serial_number;
            Some(serial.to_owned())
        }
        other => other,
    };

    let mfa_secret = match opts.secret {
        None => {
            if opts.code == None {
                panic!("MFA secret or code is required.");
            }
            Some("".to_owned())
        }
        other => other,
    };

    let token_code = match opts.code {
        None => {
            let auth = GoogleAuthenticator::new();
            let tcode = auth.get_code(&mfa_secret.unwrap(),0).unwrap();
            Some(tcode.to_owned())
        }
        other => other,
    };

    // get sts credentials
    let sts_client = StsClient::new_with_client(client, region.clone());
    let sts_request = GetSessionTokenRequest {
        duration_seconds: Some(60*60*1),
        serial_number: serial_number.clone(),
        token_code: token_code.clone(),
    };

    let credentials:Credentials = if let Some(role_arn) = opts.rolearn {
        let sts_role = AssumeRoleRequest {
            duration_seconds: Some(60*60*1),
            role_arn: role_arn.to_owned(),
            role_session_name: "dummy".to_owned(),
            serial_number: serial_number.clone(),
            token_code: token_code.clone(),
            ..Default::default()
        };
        let assume_role_res = sts_client
            .assume_role(sts_role)
            .await
            .context("Failed assuming role");
        
        let credentials = assume_role_res
            .unwrap()
            .credentials
            .ok_or(CliError::NoCredentials)?;
        credentials
    } else {

        let credentials = sts_client
            .get_session_token(sts_request)
            .await?
            .credentials
            .ok_or(CliError::NoCredentials)?;
        credentials
    };

    // dbg!(credentials.clone());

    let identity = sts_client
        .get_caller_identity(GetCallerIdentityRequest {})
        .await?;

    let user = iam_client
        .get_user(GetUserRequest { user_name: None })
        .await?
        .user;

    let account = identity.account.ok_or(CliError::NoAccount)?;
    let ps = format!("AWS:{}@{} \\$ ", user.user_name, account);
    let shell = std::env::var("SHELL").unwrap_or_else(|_| DEFAULT_SHELL.to_owned());

    if let Some(name) = opts.session_profile {
        let c = credentials.clone();
        let profile = Profile {
            name,
            access_key_id: c.access_key_id,
            secret_access_key: c.secret_access_key,
            session_token: Some(c.session_token),
            region: Some(region.name().to_owned()),
        };
        update_credentials(&profile)?;
    }

    if opts.shell {
        let c = credentials.clone();
        let envs: HashMap<&str, String> = [
            ("AWS_ACCESS_KEY", c.access_key_id),
            ("AWS_SECRET_KEY", c.secret_access_key),
            ("AWS_SESSION_TOKEN", c.session_token),
            ("PS1", ps.clone()),
        ]
        .iter()
        .cloned()
        .collect();

        Command::new(shell.clone()).envs(envs).status()?;
    }

    if opts.export {
        Shell::from(shell.as_str()).export(
            credentials.access_key_id,
            credentials.secret_access_key,
            credentials.session_token,
            ps,
        );
    }

    Ok(())
}
