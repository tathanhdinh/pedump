extern crate clap;
extern crate goblin;
#[macro_use] extern crate failure;
extern crate tabwriter;
extern crate chrono;

use std::io::{Read, Write};
// use failure::{Error};

// #[macro_use] extern crate failure_derive;


static APPLICATION_NAME: &'static str = "pedump";
static APPLICATION_VERSION: &'static str = "0.1.0";
static APPLICATION_AUTHOR: &'static str = "TA Thanh Dinh <tathanhdinh@gmail.com>";
static APPLICATION_ABOUT: &'static str = "A PE dumper";

static ARGUMENT_FILE: &'static str = "input file";
static ARGUMENT_EXPORT_DATA_DIR: &'static str = "dump export data directory";

fn main() {
    if let Err(err) = run() {
        println!("Error: {}", err);
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
        .arg(clap::Arg::with_name(ARGUMENT_EXPORT_DATA_DIR)
                .short("e")
                .long("export"))
        .get_matches();

    let input_file = matches.value_of(ARGUMENT_FILE).unwrap(); // should not panic
    let file_mdt = std::fs::metadata(input_file)?;
    if file_mdt.file_type().is_file() {
        let mut fd = std::fs::File::open(input_file)?;
        let mut buffer = Vec::new();
        fd.read_to_end(&mut buffer)?;
        let pe_object = goblin::pe::PE::parse(&buffer)?;
        // println!("PE {:#?}", &pe_object);

        if matches.is_present(ARGUMENT_EXPORT_DATA_DIR) {
            dump_pe(&pe_object, true, false)?;
        }
        else {
            dump_pe(&pe_object, false, false)?;
        }
    }

    Ok(())
}

fn dump_pe(pe_object: &goblin::pe::PE, show_export: bool, verbose: bool) -> Result<(), failure::Error> {
    let lib_or_exe = if pe_object.is_lib { "library" } else { "executable" };
    let arch = if pe_object.is_64 { "PE32+" } else { "PE32" };
    println!("{} {}", arch, lib_or_exe);

    // if pe_object.is_64 {
    //     println!("{}", "PE32+");
    // }
    // else {
    //     println!("{}", "PE32");
    // }

    if show_export {
        if let Some(ref export) = pe_object.export_data {
            // show export directory table
            let name = if let Some(ref name) = export.name { name } else { "name not found" };
            println!("Export Directory ({})", name);

            let mut output_format_strs = Vec::new();

            let dir_table = &export.export_directory_table;
            output_format_strs.push(format!("Export flags:\t{}", dir_table.export_flags));

            let dt = chrono::NaiveDateTime::from_timestamp(dir_table.time_date_stamp as i64, 0);
            output_format_strs.push(format!("Time/Date stamp:\t{}", dt));
            output_format_strs.push(format!("Major version:\t{}", dir_table.major_version));
            output_format_strs.push(format!("Minor version:\t{}", dir_table.minor_version));
            output_format_strs.push(format!("Name rva:\t0x{:x}", dir_table.name_rva));
            output_format_strs.push(format!("Ordinal base:\t{}", dir_table.ordinal_base));
            output_format_strs.push(format!("Address table entries:\t{}", dir_table.address_table_entries));
            output_format_strs.push(format!("Number of name pointer:\t{}", dir_table.number_of_name_pointers));
            output_format_strs.push(format!("Export address table rva:\t0x{:x}", dir_table.export_address_table_rva));
            output_format_strs.push(format!("Name pointer rva:\t0x{:x}", dir_table.name_pointer_rva));
            output_format_strs.push(format!("Ordinal table rva:\t0x{:x}", dir_table.ordinal_table_rva));

            let mut tw = tabwriter::TabWriter::new(std::io::stdout()).padding(4);
            writeln!(&mut tw, "{}", output_format_strs.join("\r\n"))?;
            tw.flush()?;

            Ok(())
        }
        else {
            // println!("{}", "The ")
            // failure::err_msg("sdfsdf")
            Err(format_err!("Export directory not found"))
        }
    }
    else {
        Ok(())
    }
}