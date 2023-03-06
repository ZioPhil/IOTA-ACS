use std::fs::File;
use std::{fs};
use identity_iota::account::{Account, AccountBuilder, AutoSave, Error, IdentitySetup, MethodContent, Result};
use identity_iota::client::{Client as identityClient, ClientBuilder, CredentialValidationOptions, CredentialValidator, FailFast, Resolver, ResolverBuilder};
use identity_iota::core::{FromJson, OneOrMany, Timestamp, ToJson, Url};
use identity_iota::credential::{Credential, Presentation, PresentationBuilder};
use identity_iota::iota_core::{IotaDID, Network};
use identity_iota::account_storage::{Stronghold};
use identity_iota::crypto::{GetSignature, GetSignatureMut, Proof, ProofOptions, SetSignature};
use std::path::PathBuf;
use std::io::{BufRead, BufReader, Read, Write};
use identity_iota::did::verifiable::VerifierOptions;
use iota_client::{Client, Result as clientResult};
use std::sync::Arc;
use iota_client::bee_message::payload::Payload;

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

pub async fn create_client_iota(network_name: String, url: String) -> clientResult<Client> {
    let client: Client = Client::builder()
        .with_network(&network_name)
        .with_primary_node(url.as_str(), None, None)?
        .finish()
        .await?;
    Ok(client)
}

pub async fn create_client_identity(network_name: String, url: String) -> Result<identityClient> {
    let network = Network::try_from_name(network_name)?;

    let client: identityClient = ClientBuilder::new()
        .network(network.clone())
        .primary_node(url.as_str(), None, None)?
        .build()
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

pub async fn create_ipfs_content() -> Result<()> {
    let model = fs::read_to_string("model.json").unwrap().into_bytes().to_owned();
    write_content(String::from_utf8(model).unwrap());
    Ok(())
}

pub async fn upload_to_tangle(user: &Account, cid: String, mut vc: String, index: &String) -> Result<()> {
    let client = create_client_iota(String::from("dev"), String::from("http://127.0.0.1:14265")).await.unwrap();

    vc.push('\n');
    vc.push_str(&cid);

    let mut vccid = Signable::new(vc.clone());
    user.sign("SCKey", &mut vccid, Default::default()).await?;

    let mut tag = String::from("IOTAFederatedLearning#");
    tag.push_str(&index);
    let content = serde_json::to_vec(&vccid).unwrap();

    let message = client
        .message()
        .with_index(tag)
        .with_data(content)
        .finish()
        .await;

    Ok(())
}

pub async fn get_tangle_data(index: &String, issuer_did: &IotaDID) -> Result<Vec<String>> {
    let mut res = Vec::new();
    let client = create_client_iota(String::from("dev"), String::from("http://127.0.0.1:14265")).await.unwrap();

    let identity_client: identityClient = match create_client_identity(String::from("dev"), String::from("http://127.0.0.1:14265")).await {
        Ok(client) => client,
        Err(err) => return Err(err),
    };

    let resolver_builder: ResolverBuilder = ResolverBuilder::new();
    let resolver: Resolver = resolver_builder.client(Arc::from(identity_client)).build().await.unwrap();

    let mut tag = String::from("IOTAFederatedLearning#");
    tag.push_str(&index);

    let fetched_message_ids = client.get_message().index(tag).await.unwrap();
    for message_id in fetched_message_ids.iter() {
        let payload = client.get_message().data(&message_id).await.unwrap().payload().to_owned().unwrap();

        if let Payload::Indexation(box_m) = payload {
            let data: Signable = serde_json::from_slice(box_m.as_ref().data()).unwrap();
            let mut lines = data.data.lines();
            let credential: Credential = Credential::from_json(lines.next().unwrap()).unwrap();
            let cid = lines.next().unwrap();

            let sub = match credential.clone().credential_subject {
                OneOrMany::One(sub) => sub,
                OneOrMany::Many(_vec) => return Err(Error::IdentityNotFound),
            };
            let user_did: IotaDID = IotaDID::parse(sub.id.unwrap().to_string()).unwrap();

            //Verify the signature on the data uploaded to the tangle
            let doc = resolver.resolve(&user_did).await.unwrap().document;
            let ver: bool = doc
                .verify_data(&data, &VerifierOptions::default())
                .is_ok();
            if ver {
                let issuer_doc = resolver.resolve(&issuer_did).await.unwrap().document;

                //Verify the VC contained in the data uploaded to the tangle
                CredentialValidator::validate(
                    &credential,
                    &issuer_doc,
                    &CredentialValidationOptions::default(),
                    FailFast::FirstError,
                ).unwrap();

                res.push(cid.to_string());
            }
        }
    }
    Ok(res)
}