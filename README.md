# Password Trainer

So, you have a lot of passwords and because you are a cautious being, you chose different passwords for each account. That's great! But do you really remember all of them? I don't.

That's what this password trainer for! It works like a vocabulary trainer, you enter the password and the password trainer checks if you can still remember it.

**Don't use this tool with your actual passwords unless you can be absolutely sure that nobody will every have access to the `store.bin` file.**

The passwords are not stored in plaintext but as salted hashes.

## Usage

    git clone https://github.com/cyd3r/password-trainer
    cd password-trainer
    cargo run

Every time you launch the program, you will be asked to give a master password. Once you've typed it in you will get the first few characters of the corresponding hash. You can use this hash to check if you've typed the correct master password. **The master password will never be verified!**

After the hash has been verified, you can choose to either

- add a new password
- edit an existing password
- remove an existing password
- train with stored passwords
