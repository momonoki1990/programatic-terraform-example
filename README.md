## Settings

### Environment Variables

```
# Credentials
export AWS_ACCESS_KEY_ID=
export AWS_SECRET_ACCESS_KEY=
export AWS_DEFAULT_REGION=

export AWS_DEFAULT_REGION=
export GITHUB_TOKEN=
export TF_VAR_my_domain=
export TF_VAR_aws_account_id=
export TF_VAR_github_account_name=
export TF_VAR_github_repository=
export TF_VAR_db_root_username=
export TF_VAR_db_root_user_password=
```

## Deploy

```
# if new module
$ terraform get

# dry run
$ terraform plan

# deploy
$ terraform apply
```