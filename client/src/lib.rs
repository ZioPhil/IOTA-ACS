use std::fs::File;
use std::io;
use identity_iota::account::{Account, AccountBuilder, AutoSave, IdentitySetup, MethodContent, Result};
use identity_iota::client::{ClientBuilder};
use identity_iota::core::{FromJson, KeyComparable, Timestamp, ToJson, Url};
use identity_iota::credential::{Credential, Presentation, PresentationBuilder};
use identity_iota::iota_core::{IotaDID, Network};
use identity_iota::account_storage::{KeyLocation, Stronghold};
use identity_iota::crypto::ProofOptions;
use std::path::PathBuf;
use std::io::{BufRead, BufReader, Read, Write};
use sha2::{Sha256, Digest};

pub fn write_did(did: &IotaDID) -> std::io::Result<()> {
    let mut output = File::create("did.txt")?;
    write!(output, "{}", did)
}

pub fn write_vc(vc: &str) -> std::io::Result<()> {
    let mut output = File::create("vc.txt")?;
    write!(output, "{}", vc)
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

pub async fn create_ipfs_content(user: &Account) -> Result<String> {
    let mut file = File::open("model.json").unwrap();

    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).unwrap();
    let hash = hasher.finalize();
    let mut hex_hash = base16ct::lower::encode_string(&hash).to_owned();
    println!("Hex-encoded hash: {}", hex_hash);

    user
        .sign("#SCKey", &mut hex_hash, ProofOptions::default())
        .await?;

    let key = user.document().extract_signing_keys().get(0).unwrap().unwrap().data().try_decode();

    let a = user

    let reader = BufReader::new(file);
    let mut model = reader.lines().enumerate().next().unwrap().1.unwrap().to_owned();

    model.push_str("\n");
    model.push_str(&hex_hash);
    Ok(model)
}