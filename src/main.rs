use std::{fs, io};
use std::num::NonZeroU32;
use dialoguer::{theme::ColorfulTheme, theme::Theme, Select, Password, Input, Confirm};

mod password_database;
use password_database::PasswordDatabase;

const STORE_FILENAME: &str = "store.bin";

#[derive(Debug)]
enum Error {
    CancelMasterPassword,
    UIError,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CancelMasterPassword => write!(f, "Cancel master"),
            Self::UIError => write!(f, "UI error"),
        }
    }
}

impl std::convert::From<io::Error> for Error {
    fn from(_: io::Error) -> Self {
        Error::UIError
    }
}

fn add_account<'t>(db: &mut PasswordDatabase, theme: &'t dyn Theme) -> Result<(), Error> {
    let username: String = Input::with_theme(theme)
        .with_prompt("Account name")
        .interact_text()?;
    let password: String = Password::with_theme(theme)
        .with_prompt("Password")
        .interact()?;

    db.store_password(&username, &password);
    Ok(())
}

fn remove_account<'t>(db: &mut PasswordDatabase, theme: &'t dyn Theme) -> Result<(), Error> {
    let username: String = Input::with_theme(theme)
        .with_prompt("Account name")
        .interact_text()?;
    db.remove_password(&username);
    Ok(())
}

fn edit_account<'t>(db: &mut PasswordDatabase, theme: &'t dyn Theme) -> Result<(), Error> {
    let username: String = Input::with_theme(theme)
        .with_prompt("Account name")
        .interact_text()?;

    if db.contains_username(&username) {
        let password: String = Password::with_theme(theme)
            .with_prompt("Password")
            .interact()?;
        db.store_password(&username, &password);
    }
    else {
        println!("This account does not exist");
    }
    Ok(())
}

fn train<'t>(db: &PasswordDatabase, theme: &'t dyn Theme) -> Result<(), Error> {
    loop {
        match db.get_random_username() {
            Some(username) => {
                loop {
                    let password: String = Password::with_theme(theme)
                        .with_prompt(format!("Password for {} (leave empty to abort)", username))
                        .allow_empty_password(true)
                        .interact()?;

                    if password.is_empty() {
                        println!("Empty password, abort training");
                        return Ok(());
                    }

                    match db.verify_password(username, &password) {
                        Ok(()) => {
                            println!("Good!");
                            break;
                        },
                        Err(_err) => println!("Incorrect, please try again"),
                    }
                }
            },
            None => {
                break;
            }
        }
    }
    Ok(())
}

fn db_load_or_new<'t>(theme: &'t dyn Theme) -> Result<PasswordDatabase, Error> {
    match fs::read(STORE_FILENAME) {
        Ok(data) => {
            let mut db: PasswordDatabase = bincode::deserialize(&data).expect("Deserialization failed");
            let mut master_password: String;
            loop {
                master_password = Password::with_theme(theme)
                    .with_prompt("Master password (leave empty to abort)")
                    .allow_empty_password(true)
                    .interact()?;

                if master_password.is_empty() {
                    return Err(Error::CancelMasterPassword);
                }

                db.set_master_password(master_password);

                let is_ok = Confirm::with_theme(theme)
                    .with_prompt(format!("Does {} look familiar?", db.get_hashed_master_password()))
                    .default(true)
                    .interact()?;
        
                if is_ok { break; }
            }
            Ok(db)
        },
        Err(_err) => {
            println!("Creating a storage file for you");
            let master_password = Password::with_theme(theme)
                .with_prompt("Set master password")
                .interact()?;
            let mut db = PasswordDatabase::new(NonZeroU32::new(10_000).unwrap());
            db.set_master_password(master_password);
            println!("{} is your check", db.get_hashed_master_password());
            Ok(db)
        },
    }
}

fn main_loop<'t>(db: &mut PasswordDatabase, theme: &'t dyn Theme) -> Result<(), Error> {
    let mut just_started = true;

    loop {
        let sel_add = 0;
        let sel_edit = 1;
        let sel_remove = 2;
        let sel_train = 3;
        let sel_exit;
        let mut selections = vec!["Add a new account"];
        if db.num_accounts() > 0 {
            sel_exit = 4;
            selections.push("Edit an existing account");
            selections.push("Remove an account");
            selections.push("Train passwords");
        }
        else {
            sel_exit = 1;
        }
        selections.push("Exit");

        let default_sel;
        if just_started {
            default_sel = if db.num_accounts() == 0 { sel_add } else { sel_train };
            just_started = false;
        }
        else {
            default_sel = sel_exit;
        }

        let selection = Select::with_theme(theme)
            .with_prompt("What do you want to do?")
            .default(default_sel)
            .items(&selections)
            .interact()?;

        if selection == sel_exit {
            break;
        }
        else if selection == sel_add {
            add_account(db, theme)?;
        }
        else if selection == sel_remove {
            remove_account(db, theme)?;
        }
        else if selection == sel_edit {
            edit_account(db, theme)?;
        }
        else if selection == sel_train {
            train(db, theme)?;
        }
    }
    Ok(())
}

fn run() -> Result<(), Error> {
    let theme = &ColorfulTheme::default();

    let mut db = db_load_or_new(theme)?;
    println!("Registered passwords: {}", db.num_accounts());
    main_loop(&mut db, theme)?;

    let encoded = bincode::serialize(&db).expect("Serialization failed");
    fs::write(STORE_FILENAME, encoded).expect("Could not write binary file");
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        println!("{}", err);
    }
}
