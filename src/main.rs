use anyhow::{anyhow, Result};
use structopt::StructOpt;

mod crack;
mod decrypt;
mod info;
mod opt;
mod password_iter;
mod zipfile;

fn result_main() -> Result<()> {
    let opt = opt::Opt::from_args();
    let input = std::fs::read(&opt.input)?;
    let (_, records) = zipfile::parse(&input).map_err(|e| anyhow!("{}", e))?;
    if opt.show_zipfile_records {
        zipfile::show_file(&records);
    }

    // Don't want the cursor to stay hidden
    ctrlc::set_handler(move || {
        info::restore_terminal(&mut std::io::stdout());
        std::process::exit(0); // kthxbai
    })
    .expect("Error setting Ctrl-C handler");

    if opt.unroll {
        crack::crack_unrolled(opt, &records);
    } else {
        crack::crack(opt, &records);
    }
    Ok(())
}

fn main() {
    match result_main() {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{}", e);
        }
    }
}
