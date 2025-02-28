use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use configparser::ini::Ini;
use hostname;
use rcgen::{
    CertificateParams,
    CertificateSigningRequest,
    DistinguishedName,
    DnType,
    ExtendedKeyUsagePurpose,
    Ia5String,
    KeyPair,
    KeyUsagePurpose,
    SanType,
};
use xdg;

use crate::commands::cli::{Cli, CertificateSubCommands};
use crate::util::{CONFIG_DIR_PREFIX,sign_data};

//#[derive(Debug)]
//struct CertificateConfig {
//    email: Option<String>,
//    organization: Option<String>,
//    common_name: Option<String>,
//}



pub struct CertificateCommand {}

impl CertificateCommand {
    pub fn handle(command: &CertificateSubCommands, cli: &Cli) {
        let mut config = Ini::new();
        //let mut controller;
        // let server = cli.server.as_ref().ok_or("Server not provided");
        let server = cli.server.clone().unwrap_or("DEFAULT".to_string());

        let config_path: PathBuf = cli.config_path.clone();
        if config_path.exists() {
            let _ = config.load(config_path);
        } else {
            println!("No config to load");
            return
        }

        // Get the keypair based on the private key path
        // TODO: This should use the config directory and append the server name?
        let server_key_path = xdg::BaseDirectories::with_profile(CONFIG_DIR_PREFIX, &server)
            .unwrap()
            .place_data_file("key.pem")
            .expect("Could not find key.pem")
            .display()
            .to_string();

        let key_pair: KeyPair = load_or_create_private_key(&server_key_path)
            .expect("Private key should exist");

        match command {
            CertificateSubCommands::Create {
                output: _,
                user_email,
                organization,
                common_name
            } => {
                let organization = organization
                    .clone()
                    .or(config.get(&server, "organization"))
                    .expect("Error, could not get organization from configuration");

                let common_name = common_name.clone().or_else(|| {
                    config.get(&server, "common_name").or_else(|| {
                        let name = config.get(&server, "name").unwrap_or_default();
                        let hostname: String = match get_hostname() {
                            Ok(name) => name,
                            Err(e) => {
                                eprintln!("Failed to get hostname: {}", e);
                                String::from("unknown")
                            }
                        };
                        Some(format!("{} - {} - {}", name, hostname, organization))
                    })
                }).expect("Could not get Common Name");

                let user_email = user_email.clone().unwrap_or_else(|| {
                    config
                        .get(&server, "user_email")
                        .unwrap_or_else(|| "default@example.com".to_string())
                });
                // Generate CSR based on key_pair and credentials provided by the user.
                let csr = create_csr(key_pair, common_name, user_email, organization);
                // Sign the CSR with the users PGP key

                //  Upload the CSR to the server

                //  Check for an error, if there is no error get the Certificate from the
                //  request and load it into the browsers PKI
            }
        }
    }
}

/*
pub struct CertificateController<'a> {
    config: &'a mut Ini,
    config_path: PathBuf,
    server: String
}

impl<'a> CertificateController<'a> {
    fn new(config: &'a mut Ini, config_path: PathBuf, server: String) -> CertificateController<'a> {
        CertificateController {
            config,
            config_path,
            server
        }
    }

    /*
    fn status(&mut self) {

    }
    */


    fn create(
        &mut self,
        _common_name: String,
        _user_email: String,
        _organization: String,
        _output: Option<PathBuf>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Check certificate validity
        // If certificate is valid, return
        //
        //
        // if the certificate is invalid or doesn't exist create CSR
        let csr = self.create_csr(
            _common_name,
            _user_email,
            _organization,
        )?;

        Ok(())
    }
}
*/

fn create_csr(
    key_pair: KeyPair,
    common_name: String,
    email: String,
    organization: String,
) -> Result<CertificateSigningRequest, Box<dyn std::error::Error>> {
    let mut params = CertificateParams::new(vec![common_name.clone()]).expect("Certificate Parameters could not be created");

    // Force the CA to not be a Certificate Authority
    // We should also force this on the server side as well
    params.is_ca = rcgen::IsCa::NoCa;

    // Compulsory Fields
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &common_name);
    dn.push(DnType::OrganizationName, &organization);
    // Optional Fields


    // Set Distinguished Name
    params.distinguished_name = dn;

    // SANS
    let mut sans: Vec<SanType> = Vec::new();
    let hostname = Ia5String::try_from(get_hostname()?).unwrap();
    sans.push(SanType::DnsName(hostname));
    let ia5email = Ia5String::try_from(email).unwrap();
    sans.push(SanType::Rfc822Name(ia5email));


    // Add Key Usage and Extended Key Usage
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    // We only want to generate Client Authentication Certificates
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let csr: CertificateParams = params.clone();
    Ok(csr.serialize_request(&key_pair)?)
}

fn get_hostname() -> Result<String, String> {
    hostname::get()
        .map_err(|e| format!("Failed to get hostname: {}", e))
        .and_then(|name| name.into_string().map_err(|os_str| {
            format!("Failed to convert hostname to string: {:?}", os_str)
        }))
}

fn load_or_create_private_key(file_path: &str) -> Result<KeyPair, Box<dyn std::error::Error>> {
    let path = Path::new(file_path);

    if path.exists() {
        // Load the private key from the file
        let mut file = fs::File::open(path)?;
        let mut pem_str = String::new();
        file.read_to_string(&mut pem_str)?;
        // TODO: Decrypt the private key using the users PGP key prior to loading
        let key_pair = KeyPair::from_pem(&pem_str);
        println!("Loaded private key from {}", file_path);
        Ok(key_pair?)
    } else {
        // Create a new private key
        let key_pair = KeyPair::generate()?;
        let private_key_pem = key_pair.serialize_pem();
        let mut file = fs::File::create(path)?;
        // TODO: Encrypt the private key using the users PGP key prior to writing.
        // Ideally we should also support writing the key to a hardware security token. This also
        // requires support for signing with the hardware token backed key as well as support for
        // handling that in the browser.
        file.write_all(private_key_pem.as_bytes())?;
        println!("Writing private key to {}", file_path);
        Ok(key_pair)
    }
}
