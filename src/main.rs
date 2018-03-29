extern crate clap;
extern crate goblin;
#[macro_use] extern crate failure;

// #[macro_use] extern crate failure_derive;


static APPLICATION_NAME: &'static str = "pedump";
static APPLICATION_VERSION: &'static str = "0.1.0";
static APPLICATION_AUTHOR: &'static str = "TA Thanh Dinh <tathanhdinh@gmail.com>";
static APPLICATION_ABOUT: &'static str = "A PE dumper";

static ARGUMENT_FILE: &'static str = "input file";

fn main() {
    // println!("Hello, world!");
    let matches = clap::App::new(APPLICATION_NAME)
        .version(APPLICATION_VERSION)
        .author(APPLICATION_AUTHOR)
        .about(APPLICATION_ABOUT)
        .arg(clap::Arg::with_name(ARGUMENT_FILE)
                .required(true)
                .index(1))
        .get_matches();

    let input_file = matches.value_of(ARGUMENT_FILE).unwrap(); // should not panic

}

fn run() -> Result<(), failure::Error> {
}