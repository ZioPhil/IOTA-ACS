use std::fs::File;
use std::{fs, io};
use identity_iota::account::{Account, AccountBuilder, AutoSave, IdentitySetup, MethodContent, Result};
use identity_iota::client::{ClientBuilder};
use identity_iota::core::{FromJson, KeyComparable, Timestamp, ToJson, Url};
use identity_iota::credential::{Credential, Presentation, PresentationBuilder};
use identity_iota::iota_core::{IotaDID, Network};
use identity_iota::account_storage::{KeyLocation, Signature, Stronghold};
use identity_iota::crypto::ProofOptions;
use std::path::PathBuf;
use std::io::{BufRead, BufReader, Read, Write};
use sha2::{Sha256, Digest};
use std::str::from_utf8;
use bstr::ByteVec;
use iota_client::bee_message::output::Output::SignatureLockedDustAllowance;

extern crate serde;

pub fn write_did(did: &IotaDID) -> std::io::Result<()> {
    let mut output = File::create("did.txt")?;
    write!(output, "{}", did)
}

pub fn write_vc(vc: &str) -> std::io::Result<()> {
    let mut output = File::create("vc.txt")?;
    write!(output, "{}", vc)
}

pub fn write_content(content: String) -> std::io::Result<()> {
    let mut output = File::create("ipfs_content.txt")?;
    write!(output, "{}", content)
}

pub fn read_did() -> std::io::Result<String> {
    let file = File::open("did.txt").unwrap();
    let reader = BufReader::new(file);
    reader.lines().enumerate().next().unwrap().1
}

pub fn read_vc() -> std::io::Result<String> {
    let file = File::open("vc.txt").unwrap();
    let reader = BufReader::new(file);
    reader.lines().enumerate().next().unwrap().1
}

pub async fn create_builder(password: String, network_name: String, url: String) -> Result<AccountBuilder> {
    let stronghold_path: PathBuf = "./strong.hodl".into();
    let stronghold: Stronghold = Stronghold::new(&stronghold_path, password, None).await?;

    let network = Network::try_from_name(network_name)?;

    let builder: AccountBuilder = Account::builder()
        .autosave(AutoSave::Every)
        .autopublish(true)
        .storage(stronghold)
        .client_builder(
            ClientBuilder::new()
                .network(network.clone())
                .primary_node(url.as_str(), None, None)?,
        );
use std::str::from_utf8;
    Ok(builder)
}

pub async fn create_identity(builder: &mut AccountBuilder) -> Result<Account> {
    match builder.create_identity(IdentitySetup::default()).await {
        Ok(mut identity) => {
            identity
                .update_identity()
                .create_method()
                .content(MethodContent::GenerateEd25519)
                .fragment("SCKey")
                .apply()
                .await?;
            Ok(identity)
        },
        Err(err) => {
            Err(err)
        }
    }
}

pub async fn load_identity(builder: &mut AccountBuilder, did: IotaDID) -> Result<Account> {
    match builder.load_identity(did).await {
        Ok(issuer) => Ok(issuer),
        Err(err) => Err(err),
    }
}

pub async fn create_vp(credential_json: &String, holder: &Account, challenge: (String, Timestamp)) -> Result<String> {
    let credential: Credential = Credential::from_json(credential_json.as_str())?;

    let mut presentation: Presentation = PresentationBuilder::default()
        .holder(Url::parse(holder.did().as_ref())?)
        .credential(credential)
        .build()?;

    holder
        .sign(
            "#SCKey",
            &mut presentation,
            ProofOptions::new().challenge(challenge.0).expires(challenge.1),
        )
        .await?;

    let presentation_json: String = presentation.to_json()?;

    Ok(presentation_json)
}

pub async fn create_ipfs_content(user: &Account) -> Result<()> {
    let mut model = fs::read_to_string("model.json").unwrap().into_bytes().to_owned();

    let b = user.document().default_signing_method().unwrap();
    let c = KeyLocation::from_verification_method(b).unwrap();
    let a = user.storage().key_sign(user.did(), &c, model).await.unwrap();
    let sig = serde_json::to_string(&a).unwrap().to_owned();

    let mut model = fs::read_to_string("model.json").unwrap().to_owned();
    model.push_str("\n");
    model.push_str(&sig);

    write_content(model);

    Ok(())
}