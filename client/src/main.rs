use std::io;
use std::net::{TcpStream};
use std::io::{Read};
use std::str::from_utf8;
use bstr::B;
use std::io::prelude::*;
use identity_iota::account::{Account, AccountBuilder};
use identity_iota::core::Timestamp;
use identity_iota::iota_core::IotaDID;
use std::process::Command;

mod lib;

#[tokio::main]
async fn main() {
    let stdin = io::stdin();
    let mut user: Option<Account> = None;

    println!("Insert Stronghold password:");
    println!("If the stronghold does not exists a new one will be created with the password of your choice");
    let password = stdin.lock().lines().next().unwrap().unwrap();

    let mut builder: AccountBuilder = match lib::create_builder(password, String::from("dev"), String::from("http://127.0.0.1:14265")).await {
        Ok(res) => {
            println!("\nBuilder created!");
            res
        },
        Err(err) => {
            eprintln!("Error: {:?}", err);
            return
        },
    };

    println!("\nWhat do you want to do? (Insert the right number)\n1) Create my identity on the IOTA tangle\n2) I already have an identity\n");
    for line in stdin.lock().lines() {
        let msg = line.unwrap();
        match msg.as_str() {
            "1" => {
                user = Some(match lib::create_identity(&mut builder).await {
                    Ok(identity) => {
                        println!("Identity created! DID: {}", identity.did());
                        identity
                    },
                    Err(err) => {
                        eprintln!("Error: {:?}", err);
                        return
                    },
                });
                match lib::write_did(user.as_ref().unwrap().did()) {
                    Ok(..) => println!("Did saved in did.txt"),
                    Err(err) => {
                        eprintln!("Error: {:?}", err);
                        return
                    },
                }
                break;
            },
            "2" => {
                let did: String = match lib::read_did() {
                    Ok(did) => did,
                    Err(err) => {
                        eprintln!("Error: {:?}", err);
                        return
                    },
                };
                let user_did: IotaDID = match IotaDID::parse(did) {
                    Ok(did) => did,
                    Err(err) => {
                        eprintln!("Error: {:?}", err);
                        return
                    },
                };
                user = Some(match lib::load_identity(&mut builder, user_did).await {
                    Ok(identity) => {
                        println!("Identity loaded! DID: {}", identity.did());
                        identity
                    },
                    Err(err) => {
                        eprintln!("Error: {:?}", err);
                        return
                    },
                });
                break;
            },
            _ => {
                println!("Wrong input! Please retry.\n");
                println!("\nWhat do you want to do? (Insert the right number)\n1) Create my identity on the IOTA tangle\n2) I already have an identity\n");
            },
        };
    }

    match TcpStream::connect("localhost:3333") {
        Ok(mut stream) => {
            println!("\nSuccessfully connected to server in port 3333");
            let mut data = [0 as u8; 564]; //564 byte buffer

            println!("\nWhat do you want to do? (Insert the right number)\n1)Sign up\n2)Sign in\n0) Close the application\n");
            for line in stdin.lock().lines() {
                let msg = line.unwrap();
                match msg.as_str() {
                    "0" => {
                        stream.write(b"shutdown").unwrap();
                        println!("\nClient terminated.");
                        return
                    },
                    "1" => {
                        let did: String = match lib::read_did() {
                            Ok(did) => did,
                            Err(err) => {
                                eprintln!("Error: {:?}", err);
                                return
                            },
                        };
                        stream.write(b"vc").unwrap();

                        match stream.read(&mut data) {
                            Ok(..) => println!(),
                            Err(err) => {
                                eprintln!("Error: {:?}", err);
                                return
                            },
                        };

                        stream.write(B(did.as_str())).unwrap();

                        let vc: &str = match stream.read(&mut data) {
                            Ok(size) => {
                                from_utf8(&data[0..size]).unwrap()
                            }
                            Err(err) => {
                                eprintln!("Error: {:?}", err);
                                return
                            },
                        };

                        match lib::write_vc(vc) {
                            Ok(..) => println!("VC created and saved in vc.txt"),
                            Err(err) => {
                                eprintln!("Error: {:?}", err);
                                return
                            },
                        }
                    },
                    "2" => {
                        stream.write(b"vp").unwrap();

                        let challenge: String = match stream.read(&mut data) {
                            Ok(size) => {
                                from_utf8(&data[0..size]).unwrap().to_string()
                            }
                            Err(err) => {
                                eprintln!("Error: {:?}", err);
                                return
                            },
                        };

                        stream.write(b"ack").unwrap();

                        let timestr: &str = match stream.read(&mut data) {
                            Ok(size) => from_utf8(&data[0..size]).unwrap(),
                            Err(err) => {
                                eprintln!("Error: {:?}", err);
                                return
                            },
                        };
                        let timestamp: Timestamp = match Timestamp::parse(timestr) {
                            Ok(t) => t,
                            Err(err) => {
                                eprintln!("Error: {:?}", err);
                                return
                            },
                        };

                        let vc: String = match lib::read_vc() {
                            Ok(vc) => vc,
                            Err(err) => {
                                eprintln!("Error: {:?}", err);
                                return
                            },
                        };

                        let vp: String = match lib::create_vp(&vc, user.as_mut().unwrap(), (challenge, timestamp)).await {
                            Ok(vp) => {
                                println!("VP created!");
                                vp
                            },
                            Err(err) => {
                                eprintln!("Error: {:?}", err);
                                return
                            },
                        };

                        stream.write(B(vp.as_str())).unwrap();

                        match stream.read(&mut data) {
                            Ok(..) => {
                                break;
                            },
                            Err(err) => {
                                eprintln!("Error: {:?}", err);
                                return
                            },
                        };
                    },
                    _ => {
                        println!("Wrong input! Please retry.\n");
                    },
                };

                println!("\nWhat do you want to do? (Insert the right number)\n1)Sign up\n2)Sign in\n0) Close the application\n");
            }

            println!("\nWhat do you want to do? (Insert the right number)\n1)Upload model to IPFS\n0) Close the application\n");
            for line in stdin.lock().lines() {
                let msg = line.unwrap();
                match msg.as_str() {
                    "0" => {
                        break;
                    },
                    "1" => {
                        match lib::create_ipfs_content(user.as_mut().unwrap()).await {
                            Ok(_) => {
                                /*
                                let upload = Command::new("ipfs")
                                    .arg("add")
                                    .arg("ipfs_content.txt")
                                    .output();

                                let output: String = match String::from_utf8(upload.unwrap().stdout) {
                                    Ok(res) => res,
                                    Err(err) => {
                                        eprintln!("Error: {:?}", err);
                                        return
                                    },
                                };

                                let a = output.split(' ').collect::<Vec<&str>>().get(1).unwrap().to_string();
                                println!("Cid: {}", a);

                                 */
                                println!("E' andata!!");
                            },
                            Err(err) => {
                                eprintln!("Error: {:?}", err);
                                return
                            },
                        };
                    },
                    _ => {
                        println!("Wrong input! Please retry.\n");
                    },
                };
                println!("\nWhat do you want to do? (Insert the right number)\n1)Upload model to IPFS\n0) Close the application\n");
            }
            stream.write(b"shutdown").unwrap();
            println!("\nClient terminated.");
            return
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
}