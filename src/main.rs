extern crate clap;
extern crate goblin;
#[macro_use] extern crate failure;

use std::{io::Read};
// use failure::{Error};

// #[macro_use] extern crate failure_derive;


static APPLICATION_NAME: &'static str = "pedump";
static APPLICATION_VERSION: &'static str = "0.1.0";
static APPLICATION_AUTHOR: &'static str = "TA Thanh Dinh <tathanhdinh@gmail.com>";
static APPLICATION_ABOUT: &'static str = "A PE dumper";

static ARGUMENT_FILE: &'static str = "input file";

fn main() {
    match run() {
        Ok(_) => {

        },
        
        Err(err) => {
            println!("Error: {}", err);
        }
    }
}

fn run() -> Result<(), failure::Error> {
    let matches = clap::App::new(APPLICATION_NAME)
        .version(APPLICATION_VERSION)
        .author(APPLICATION_AUTHOR)
        .about(APPLICATION_ABOUT)
        .arg(clap::Arg::with_name(ARGUMENT_FILE)
                .required(true)
                .index(1))
        .get_matches();

    let input_file = matches.value_of(ARGUMENT_FILE).unwrap(); // should not panic
    let file_mdt = std::fs::metadata(input_file)?;
    if file_mdt.file_type().is_file() {
        let mut fd = std::fs::File::open(input_file)?;
        let mut buffer = Vec::new();
        fd.read_to_end(&mut buffer)?;
        let pe_object = goblin::pe::PE::parse(&buffer)?;
        // println!("PE {:#?}", &pe_object);
        dump_pe(&pe_object)?;
    }

    Ok(())
}

fn dump_pe(pe_object: &goblin::pe::PE) -> Result<(), failure::Error> {
    // println!("{}", )
    if pe_object.is_64 {
        println!("{}", "PE32+");
    }
    else {
        println!("{}", "PE32");
    }
    Ok(())
}