use std::fs::File;
use std::{fs, io};
use identity_iota::account::{Account, AccountBuilder, AutoSave, IdentitySetup, MethodContent, Result};
use identity_iota::client::{ClientBuilder};
use identity_iota::core::{FromJson, Timestamp, ToJson, Url};
use identity_iota::credential::{Credential, Presentation, PresentationBuilder};
use identity_iota::iota_core::{IotaDID, Network};
use identity_iota::account_storage::{Stronghold};
use identity_iota::crypto::{Ed25519, GetSignature, GetSignatureMut, JcsEd25519, Proof, ProofOptions, PublicKey, SetSignature};
use std::path::PathBuf;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::Command;
use sha2::{Sha256, Digest};
use std::str::from_utf8;
use bstr::ByteVec;
use identity_iota::did::verifiable::VerifierOptions;
use sha2::digest::Mac;
use iota_client::{Client, Result as clientResult};
use iota_client::bee_message::MessageId;
use std::str::FromStr;

extern crate serde;

#[derive(serde::Serialize, serde::Deserialize)]
struct Signable {
    data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<Proof>,
}

impl Signable {
    pub fn new(data: String) -> Self {
        Self { data, proof: None }
    }
}

impl GetSignature for Signable {
    fn signature(&self) -> Option<&Proof> {
        self.proof.as_ref()
    }
}

impl GetSignatureMut for Signable {
    fn signature_mut(&mut self) -> Option<&mut Proof> {
        self.proof.as_mut()
    }
}

impl SetSignature for Signable {
    fn set_signature(&mut self, signature: identity_iota::crypto::Proof) {
        self.proof = Some(signature)
    }
}

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

pub async fn create_client(network_name: String, url: String) -> clientResult<Client> {
    let client: Client = Client::builder()
        .with_network(&network_name)
        .with_primary_node(url.as_str(), None, None)?
        .finish()
        .await?;
    Ok(client)
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
    /*
    // prova processo di verifica successivo
    //----------------------------------------------------------------------------
    let mode = String::from_utf8(model.clone()).unwrap();
    let mut a = mode.lines();
    let model2 = a.next().unwrap();
    let hash: Signable = serde_json::from_str(a.next().unwrap()).unwrap();
    println!("Hash: {}", hash.data);

    let ver: bool = user
        .document()
        .verify_data(&hash, &VerifierOptions::default())
        .is_ok();
    println!("Verified = {}", ver);
    //----------------------------------------------------------------------------
    */
    write_content(String::from_utf8(model).unwrap());
    Ok(())
}

pub async fn upload_to_tangle(user: &Account, cid: String, mut vc: String, index: &String) -> Result<()> {
    let client = create_client(String::from("dev"), String::from("http://127.0.0.1:14265")).await.unwrap();

    vc.push('\n');
    vc.push_str(&cid);

    let mut vccid = Signable::new(vc.clone());
    user.sign("SCKey", &mut vccid, Default::default()).await?;

    let verified: bool = user
        .document()
        .verify_data(&vccid, &VerifierOptions::default())
        .is_ok();
    println!("Verified = {}", verified);

    let mut tag = String::from("IOTAFederatedLearning#");
    tag.push_str(&index);

    println!("Prima: {}", &vccid.data);
    let content = serde_json::to_vec(&vccid).unwrap();
/*
    let message = client
        .message()
        .with_index(tag)
        .with_data(content)
        .finish()
        .await;
*/
    println!("Message uploaded to tangle!");
    Ok(())
}

pub async fn get_tangle_data(index: &String) -> Result<()> {
    let client = create_client(String::from("dev"), String::from("http://127.0.0.1:14265")).await.unwrap();
    //let mut res = Vec::new();

    let mut tag = String::from("IOTAFederatedLearning#");
    tag.push_str(&index);

    let fetched_message_ids = client.get_message().index(tag).await.unwrap();
    let a = format!("{fetched_message_ids:?}");
    let a = a.split_at(a.len() - 1);
    let a = a.0.split_at(1);
    let a = a.1;

    let mut split = a.split(", ");
    let mut vec = split.collect::<Vec<&str>>();

    for (i, val) in vec.iter_mut().enumerate() {
        *val = &*val.split_at(val.len()-1).0;
        *val = &*val.split_at(10).1;
    }
    for (i, val) in vec.iter().enumerate() {
        println!("In position {} we have value {}", i, val);
        let a: &str = val.clone();
        let o = MessageId::from_json(serde_json::from_str(a).unwrap());
    }

    /*
    let data = client.get_message().data(fetched_message_ids.value).await.unwrap().payload().unwrap().data();
    let data2: Signable = serde_json::from_slice(data).unwrap();
    println!("Dopo: {}", data2.data);

     */
    Ok(())
}