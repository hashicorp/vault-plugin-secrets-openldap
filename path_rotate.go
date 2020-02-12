package openldap

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/hashicorp/go-uuid"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/queue"
)

var (
	minimumLengthOfComplexString = 8
	PasswordComplexityPrefix     = "?@09AZ"
	PwdFieldTmpl                 = "{{PASSWORD}}"
)

func (b *backend) pathRotateCredentials() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "rotate-root",
			Fields:  map[string]*framework.FieldSchema{},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.pathRotateCredentialsUpdate,
					ForwardPerformanceSecondary: true,
					ForwardPerformanceStandby:   true,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback:                    b.pathRotateCredentialsUpdate,
					ForwardPerformanceSecondary: true,
					ForwardPerformanceStandby:   true,
				},
			},
			HelpSynopsis:    pathRotateCredentialsUpdateHelpSyn,
			HelpDescription: pathRotateCredentialsUpdateHelpDesc,
		},
		{
			Pattern: "rotate-role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the static role",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback:                    b.pathRotateRoleCredentialsUpdate,
					ForwardPerformanceSecondary: true,
					ForwardPerformanceStandby:   true,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback:                    b.pathRotateRoleCredentialsUpdate,
					ForwardPerformanceSecondary: true,
					ForwardPerformanceStandby:   true,
				},
			},
			HelpSynopsis:    pathRotateRoleCredentialsUpdateHelpSyn,
			HelpDescription: pathRotateRoleCredentialsUpdateHelpDesc,
		},
	}
}

func (b *backend) pathRotateCredentialsUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, errors.New("the config is currently unset")
	}

	newPassword, err := GeneratePassword(config.Password.Formatter, config.Password.Length)
	if err != nil {
		return nil, err
	}
	oldPassword := config.LDAP.BindPassword

	// Take out the backend lock since we are swapping out the connection
	b.Lock()
	defer b.Unlock()

	// Update the password remotely.
	if err := b.client.UpdateRootPassword(config.LDAP, newPassword); err != nil {
		return nil, err
	}
	config.LDAP.BindPassword = newPassword

	// Update the password locally.
	if pwdStoringErr := storePassword(ctx, req.Storage, config); pwdStoringErr != nil {
		// We were unable to store the new password locally. We can't continue in this state because we won't be able
		// to roll any passwords, including our own to get back into a state of working. So, we need to roll back to
		// the last password we successfully got into storage.
		if rollbackErr := b.rollBackPassword(ctx, config, oldPassword); rollbackErr != nil {
			return nil, fmt.Errorf(`unable to store new password due to %s and unable to return to previous password
due to %s, configure a new binddn and bindpass to restore openldap function`, pwdStoringErr, rollbackErr)
		}
		return nil, fmt.Errorf("unable to update password due to storage err: %s", pwdStoringErr)
	}

	// Respond with a 204.
	return nil, nil
}
func (b *backend) pathRotateRoleCredentialsUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("empty role name attribute given"), nil
	}

	role, err := b.StaticRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("no static role found for role name"), nil
	}

	// In create/update of static accounts, we only care if the operation
	// err'd , and this call does not return credentials
	item, err := b.popFromRotationQueueByKey(name)
	if err != nil {
		item = &queue.Item{
			Key: name,
		}
	}

	resp, err := b.setStaticAccount(ctx, req.Storage, &setStaticAccountInput{
		RoleName: name,
		Role:     role,
	})
	if err != nil {
		b.Logger().Warn("unable to rotate credentials in rotate-role", "error", err)
		// Update the priority to re-try this rotation and re-add the item to
		// the queue
		item.Priority = time.Now().Add(10 * time.Second).Unix()

		// Preserve the WALID if it was returned
		if resp.WALID != "" {
			item.Value = resp.WALID
		}
	} else {
		item.Priority = resp.RotationTime.Add(role.StaticAccount.RotationPeriod).Unix()
	}

	// Add their rotation to the queue
	if err := b.pushItem(item); err != nil {
		return nil, err
	}

	// We're not returning creds here because we do not know if its been processed
	// by the queue.
	return nil, nil
}

// rollBackPassword uses naive exponential backoff to retry updating to an old password,
// because Active Directory may still be propagating the previous password change.
func (b *backend) rollBackPassword(ctx context.Context, config *config, oldPassword string) error {
	var err error
	for i := 0; i < 10; i++ {
		waitSeconds := math.Pow(float64(i), 2)
		timer := time.NewTimer(time.Duration(waitSeconds) * time.Second)
		select {
		case <-timer.C:
		case <-ctx.Done():
			// Outer environment is closing.
			return fmt.Errorf("unable to roll back password because enclosing environment is shutting down")
		}
		if err = b.client.UpdateRootPassword(config.LDAP, oldPassword); err == nil {
			// Success.
			return nil
		}
	}
	// Failure after looping.
	return err
}

func storePassword(ctx context.Context, s logical.Storage, config *config) error {
	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return err
	}
	if err := s.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

func GeneratePassword(formatter string, totalLength int) (string, error) {
	if err := validatePwdSettings(formatter, totalLength); err != nil {
		return "", err
	}
	pwd, err := generatePassword(totalLength)
	if err != nil {
		return "", err
	}
	if formatter == "" {
		pwd = PasswordComplexityPrefix + pwd
		return pwd[:totalLength], nil
	}
	return strings.Replace(formatter, PwdFieldTmpl, pwd[:lengthOfPassword(formatter, totalLength)], 1), nil
}

func lengthOfPassword(formatter string, totalLength int) int {
	lengthOfText := len(formatter) - len(PwdFieldTmpl)
	return totalLength - lengthOfText
}

// generatePassword returns a password of a length AT LEAST as long as the desired length,
// it may be longer.
func generatePassword(desiredLength int) (string, error) {
	b, err := uuid.GenerateRandomBytes(desiredLength)
	if err != nil {
		return "", err
	}
	result := ""
	// Though the result should immediately be longer than the desiredLength,
	// do this in a loop to ensure there's absolutely no risk of a panic when slicing it down later.
	for len(result) <= desiredLength {
		// Encode to base64 because it's more complex.
		result += base64.StdEncoding.EncodeToString(b)
	}
	return result, nil
}

const pathRotateCredentialsUpdateHelpSyn = `
Request to rotate the root credentials Vault uses for the OpenLDAP administrator account.
`

const pathRotateCredentialsUpdateHelpDesc = `
This path attempts to rotate the root credentials of the administrator account (binddn) used by Vault to manage OpenLDAP.
`

const pathRotateRoleCredentialsUpdateHelpSyn = `
Request to rotate the credentials for a static user account.
`
const pathRotateRoleCredentialsUpdateHelpDesc = `
This path attempts to rotate the credentials for the given OpenLDAP static user account.
`
