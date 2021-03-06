extern crate clap;
extern crate goblin;
#[macro_use] extern crate failure;
extern crate tabwriter;
extern crate chrono;

use std::io::{Read, Write};
// use failure::{Error};

static APPLICATION_NAME: &'static str = "pedump";
static APPLICATION_VERSION: &'static str = "0.1.0";
static APPLICATION_AUTHOR: &'static str = "TA Thanh Dinh <tathanhdinh@gmail.com>";
static APPLICATION_ABOUT: &'static str = "A PE dumper";

static ARGUMENT_FILE: &'static str = "input file";
static ARGUMENT_EXPORT_DATA_DIR: &'static str = "dump export data directory";
static ARGUMENT_VERBOSE: &'static str = "verbose";

fn main() {
    if let Err(err) = run() {
        println!("{}", err);
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
        .arg(clap::Arg::with_name(ARGUMENT_VERBOSE)
                .short("v")
                .long("verbose"))
        .get_matches();

    let input_file = matches.value_of(ARGUMENT_FILE).unwrap(); // should not panic
    let file_mdt = std::fs::metadata(input_file)?;
    if file_mdt.file_type().is_file() {
        let mut fd = std::fs::File::open(input_file)?;
        let mut buffer = Vec::new();
        fd.read_to_end(&mut buffer)?;

        // let mut count = 0;
        // for b in &buffer {
        //     print!("0x{:02x}, ", b);
        //     count = count + 1;
        //     if count % 0x10 == 0 {
        //         println!("");
        //         count = 0;
        //     }
        // }

        let pe_object = goblin::pe::PE::parse(&buffer)?;
        // println!("PE {:#?}", &pe_object);

        let show_verbose = matches.is_present(ARGUMENT_VERBOSE);
        let show_export = matches.is_present(ARGUMENT_EXPORT_DATA_DIR);

        dump_pe(&pe_object, show_export, show_verbose)?;
    }

    Ok(())
}

fn dump_pe(pe_object: &goblin::pe::PE, show_export: bool, show_verbose: bool) -> Result<(), failure::Error> {
    let locked_stdout = std::io::stdout();
    let mut locked_stdout = locked_stdout.lock();

    let lib_or_exe = if pe_object.is_lib { "library" } else { "executable" };
    let arch = if pe_object.is_64 { "PE32+" } else { "PE32" };
    // println!("{} {}", arch, lib_or_exe);
    writeln!(locked_stdout, "{} {}", arch, lib_or_exe)?;

    if show_export {
        if let Some(ref export) = pe_object.export_data {
            // show export directory table
            let name = if let Some(ref name) = export.name { name } else { "name not found" };
            // println!("Export directory ({})", name);
            writeln!(locked_stdout, "Export directory ({})", name)?;

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
            output_format_strs.push(format!("Number of name pointers:\t{}", dir_table.number_of_name_pointers));
            output_format_strs.push(format!("Export address table rva:\t0x{:x}", dir_table.export_address_table_rva));
            output_format_strs.push(format!("Name pointer rva:\t0x{:x}", dir_table.name_pointer_rva));
            output_format_strs.push(format!("Ordinal table rva:\t0x{:x}", dir_table.ordinal_table_rva));

            let mut tw = tabwriter::TabWriter::new(std::io::stdout()).padding(4);
            writeln!(&mut tw, "{}", output_format_strs.join("\r\n"))?;
            tw.flush()?;

            if show_verbose {
                write!(locked_stdout, "Entries exported by name: ")?;
                // if let Some(ref exports) = pe_object.exports {
                    let exports = &pe_object.exports;
                    let entry_num = exports.len();
                    if entry_num > 0 {
                        write!(locked_stdout, "{}...", entry_num)?;
                        locked_stdout.flush()?;
                        let _ = std::io::stdin().read(&mut [0x0u8])?;
                        writeln!(locked_stdout, "")?;

                        output_format_strs.clear();

                        // let mut export_str = Vec::new();

                        // export_str.push("Name\tRVA\tFile offset\tRe-export");
                        output_format_strs.push("Name\tRVA\tFile offset\tRe-export".to_string());

                        for export in exports {
                            let name = 
                                if let Some(ref name) = export.name { 
                                    if name.is_empty() { "*empty*" } else { name } 
                                } else { "*unknown*" };
                            // export_str.push(format!("  Name:\t{}", name));

                            // let rva = if let Some(ref rva) = export.rva { format!("0x{:x}", rva) } else { "*not found*".to_string() };
                            // export_str.push(format!("  Rva:\t{}", &rva));
                            let rva = export.rva;

                            // let offset = if let Some(ref offset) = export.offset { format!("0x{:x}", offset) } else { "*invalid*".to_string() };
                            // export_str.push(format!("  File offset:\t{}", &offset));
                            let offset = export.offset;

                            let reexport = if export.reexport.is_none() { "no" } else { "yes" };
                            // export_str.push(format!("  Re-export:\t{}", &reexport));

                            // export_str.push(format!("{}\t{}\t{}\t{}", &name, &rva, &offset, &reexport));

                            // output_format_strs.push(export_str.join("\r\n"));
                            output_format_strs.push(format!("{}\t{}\t{}\t{}", &name, rva, offset, &reexport));
                            // export_str.clear();
                        }

                        let mut tw = tabwriter::TabWriter::new(std::io::stdout()).padding(4);
                        writeln!(&mut tw, "{}", output_format_strs.join("\r\n"))?;
                        tw.flush()?;
                    }
                    else {
                        write!(locked_stdout, "0")?;
                    }
                // }
                // else {
                //     write!(locked_stdout, "None")?;
                // }

                
            }

            Ok(())
        }
        else {
            // failure::err_msg("sdfsdf")
            Err(format_err!("Export directory not found"))
        }
    }
    else {
        Ok(())
    }
}