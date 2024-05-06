## Intro

Git Repo: https://github.com/DonGoesToWork/ObsidianMain
Key Config: https://github.com/settings/keys
GCM Next: https://www.google.com/search?client=firefox-b-1-d&q=git+how+to+set+username+and+password+with+git+credential+manager

Login Details for Outlook & Github:

```
DonGoesToWork@outlook.com
Keystone1@3
```

Strongly recommend using SSH to login to GIT if Credential Manager isn't working initially. Under ideal circumstances, it should just work 'out of the box'. But, if it doesn't, just use SSH. See the following for information about setting up Git with SSH.

## Setup/Troubleshooting Steps (from my work + ChatGPT)

Everything should probably be done in Git Bash. Not Powershell.

- Generate SSH Key: ```ssh-keygen -t rsa -b 4096 -C "DonGoesToWork@outlook.com"```
	- Can just spam 'enter' through all prompts.
- Verify rsa files are generated (need 2): ```ls ~/.ssh/id_*```

Git Operations (can probably be optimized a bit I bet):

```
- git init
- git remote add origin https://github.com/DonGoesToWork/ObsidianMain
- git remote set-url origin git@github.com:DonGoesToWork/ObsidianMain.git
- git pull origin
- git pull origin master
- git branch --set-upstream-to=origin/master master
- git pull
```

If getting connection issues:

- If you have an SSH key pair generated, you need to add the private key to the SSH agent. To do this, open Git Bash or any command prompt and enter the following command: ```ssh-add ~/.ssh/id_rsa```
- If the command returns "Could not open a connection to your authentication agent", start SSH agent with: ```eval "$(ssh-agent -s)"```
- Then, run the "ssh-add" command again. If we still get a fail, check ssh-agent recognizes key: ```ssh-add -l -E sha256```
	- If we get "The agent has no identities," then basically start over. I wound up deleting the files in ```C:\Users\Destro\.ssh```
	- I don't know if it will help, but maybe try as part of this: ```git config --global --unset-all credential.helper```
	- Make sure you copy the public key from ```C:\Users\Destro\.ssh``` and now the 'output folder'. The values are different... probably relevant. That could have been the fix, but again, not 100% sure.
* ChatGPT also recommends running this to "to configure Git to use the SSH key when communicating with Github". May not be necessary, but worth noting:  ```git config --global core.sshCommand "ssh -i ~/.ssh/id_rsa -F /dev/null"```

This guide was very helpful: https://docs.github.com/en/authentication/connecting-to-github-with-ssh/using-ssh-agent-forwarding

## Warning for Setting up Future Obsidian Git Connections

> [!danger]
> I set up a bunch of git global credentials when setting up Git for Obsidian. Commands used were:
> 
> git config --global user.name "DonWork"
> git config --global user.email "DonGoesToWork@outlook.com"
> git config --global user.password "Keystone1@3"
> git config --global user.username "DonWork"
> 
> May need to clear those out when reverting back to normal git.



