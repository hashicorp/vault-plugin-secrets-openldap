# Vault Plugin: OpenLDAP Secrets Backend

This is a standalone backend plugin for use with [Hashicorp Vault](https://www.github.com/hashicorp/vault).
This plugin provides OpenLDAP functionality to Vault.

**Please note**: We take Vault's security and our users' trust very seriously. If you believe you have found a security issue in Vault, _please responsibly disclose_ by contacting us at [security@hashicorp.com](mailto:security@hashicorp.com).

## Quick Links
- Vault Website: https://developer.hashicorp.com/vault/docs
- OpenLDAP Docs: https://developer.hashicorp.com/vault/docs/secrets/ldap
- Main Project Github: https://www.github.com/hashicorp/vault

## Getting Started

This is a [Vault plugin](https://developer.hashicorp.com/vault/docs/plugins)
and is meant to work with Vault. This guide assumes you have already installed Vault
and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with Vault](https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-install).

To learn specifically about how plugins work, see documentation on [Vault plugins](https://developer.hashicorp.com/vault/docs/plugins).

## Usage

Please see [documentation for the plugin](https://developer.hashicorp.com/vault/docs/secrets/ldap)
on the Vault website.

This plugin is currently built into Vault and by default is accessed
at `openldap`. To enable this in a running Vault server:

```sh
$ vault secrets enable openldap
Success! Enabled the openldap secrets engine at: openldap/
```

## Updating the Changelog

All pull requests that introduce a user-facing change must include a changelog
entry. We use the [changie](https://changie.dev/) tool to manage these entries
and automate the release process.

---
### 1. Installing Changie

You only need to do this once. If you don't have `changie` installed, choose one of the options below.

* **Homebrew** (macOS):
    ```shell
    brew install changie
    ```
* **Go Install**:
    ```shell
    go install github.com/miniscruff/changie@latest
    ```
* **Other Methods**:
  See the [official changie installation guide](https://changie.dev/guide/installation/) for other options, including pre-compiled binaries.

---
### 2. Creating an Entry

Once your code changes are complete, create the changelog entry:

1.  **Run the command** in your terminal:
    ```shell
    changie new
    ```
2.  **Follow the prompts.** An interactive prompt will ask you to select the
    kind of change (e.g., `BREAKING CHANGES`, `NOTES`, `FEATURES`) and write a concise description of
    what you changed.

3.  **Commit the new file.** After you're done, `changie` will create a new
    YAML file in the `.changie/unreleased` directory. Commit this file along with your other
    code changes before submitting your pull request.
