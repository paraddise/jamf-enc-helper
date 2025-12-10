package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/paraddise/jamf-enc-helper/internal/dbencryption"
	"github.com/paraddise/jamf-enc-helper/internal/logger"
	"github.com/paraddise/jamf-enc-helper/internal/service"
	"github.com/spf13/cobra"
)

/*
subcommands:
- decrypt-db-key -p <phrase> -s <salt> -i <iterations> --in <db_ciphertext_in_b64>
- encrypt-db-key -p <phrase> -s <salt> -i <iterations> -k <enc_key>
- jwt-saml-token -k <enc_key> -s <salt>
- jwt-api-token -k <enc_key> -s <salt>
- get-secret -k <enc_key> -s <salt>

Options:
-p phrase: passphrase for PBKDF
-s salt: salt for PBKDF
-i iterations: iterations for PBKDF
-in input: input in base64
-k|-enc_key: encryption key, the encryption key itself, that's stored in the database
-s salt: salt for JWt, will be used for HMAC (optional)
*/

func main() {
	rootCmd := &cobra.Command{
		Use:   "jamf-enc-helper",
		Short: "Helper tool for encryption/decryption/signing Jamf secrets/tokens based on the Key stored in the Database.",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Set log level from flag
			logLevelStr, _ := cmd.Flags().GetString("log-level")
			logLevel := logger.ParseLogLevel(logLevelStr)
			logger.SetLevel(logLevel)
		},
	}

	// Add log level flag to root command (persistent, so all subcommands inherit it)
	rootCmd.PersistentFlags().String("log-level", "info", "Set the log level (debug, info, error)")

	// decrypt-db-key command
	decryptCmd := &cobra.Command{
		Use:   "decrypt-db-key",
		Short: "Decrypt a database key using PBKDF",
		RunE: func(cmd *cobra.Command, args []string) error {
			phrase, err := getOptionalString(cmd, "phrase", dbencryption.DefaultPhrase)
			if err != nil {
				return err
			}
			iterations, err := getOptionalInt(cmd, "iterations", dbencryption.DefaultIteractionCount)
			if err != nil {
				return err
			}
			input, err := getRequiredString(cmd, "in", "--in")
			if err != nil {
				return err
			}

			salt, err := getBase64Bytes(cmd, "salt", dbencryption.DefaultSalt)
			if err != nil {
				return err
			}

			logger.Debug("Decrypting key with phrase: %s, salt: %v, iterations: %d", phrase, salt, iterations)
			logger.Debug("Input: %s", input)
			// Decode input from base64
			encryptedKey, err := base64.StdEncoding.DecodeString(input)
			if err != nil {
				logger.Error("Invalid base64 input: %v", err)
				return fmt.Errorf("invalid base64 input: %w", err)
			}

			config := &dbencryption.Config{
				Phrase:          phrase,
				Salt:            salt,
				IteractionCount: iterations,
			}

			service := dbencryption.NewDBEncryptionService(config)
			decryptedKey, err := service.DecryptKeyFromDatabase(encryptedKey)
			if err != nil {
				logger.Error("Decryption failed: %v", err)
				return fmt.Errorf("decryption failed: %w", err)
			}

			// Output key data to stdout
			fmt.Println(string(decryptedKey))
			return nil
		},
	}
	decryptCmd.Flags().StringP("phrase", "p", "", "Passphrase for PBKDF")
	decryptCmd.Flags().StringP("salt", "s", "", "Salt for PBKDF base64 encoded")
	decryptCmd.Flags().IntP("iterations", "i", 0, "Iterations for PBKDF")
	decryptCmd.Flags().String("in", "", "Input ciphertext in base64")

	// encrypt-db-key command
	encryptCmd := &cobra.Command{
		Use:   "encrypt-db-key",
		Short: "Encrypt a key for database storage",
		RunE: func(cmd *cobra.Command, args []string) error {
			phrase, err := getOptionalString(cmd, "phrase", dbencryption.DefaultPhrase)
			if err != nil {
				return err
			}
			iterations, err := getOptionalInt(cmd, "iterations", dbencryption.DefaultIteractionCount)
			if err != nil {
				return err
			}
			encKey, err := getRequiredString(cmd, "enc_key", "-k")
			if err != nil {
				return err
			}

			salt, err := getBase64Bytes(cmd, "salt", dbencryption.DefaultSalt)
			if err != nil {
				logger.Error("Invalid salt: %v", err)
				return fmt.Errorf("invalid salt: %w", err)
			}

			config := &dbencryption.Config{
				Phrase:          phrase,
				Salt:            salt,
				IteractionCount: iterations,
			}

			service := dbencryption.NewDBEncryptionService(config)
			encryptedKey, err := service.EncryptKeyToDatabase([]byte(encKey))
			if err != nil {
				logger.Error("Encryption failed: %v", err)
				return fmt.Errorf("encryption failed: %w", err)
			}

			// Output key data to stdout
			fmt.Println(base64.StdEncoding.EncodeToString(encryptedKey))
			return nil
		},
	}
	encryptCmd.Flags().StringP("phrase", "p", "", "Passphrase for PBKDF")
	encryptCmd.Flags().StringP("salt", "s", "", "Salt for PBKDF base64 encoded")
	encryptCmd.Flags().IntP("iterations", "i", 0, "Iterations for PBKDF")
	encryptCmd.Flags().StringP("enc_key", "k", "", "Encryption key to encrypt")

	// jwt-saml-token command
	jwtSamlCmd := &cobra.Command{
		Use:   "jwt-saml-token",
		Short: "Generate JWT secret for SAML token",
		RunE: func(cmd *cobra.Command, args []string) error {
			encKey, err := getRequiredString(cmd, "enc_key", "-k")
			if err != nil {
				return err
			}
			salt, err := getBase64Bytes(cmd, "salt", dbencryption.DefaultSalt)
			if err != nil {
				return err
			}

			encService := service.New([]byte(encKey))
			secret := encService.GetSecret(salt)

			// Output key data to stdout
			fmt.Println(base64.StdEncoding.EncodeToString(secret))
			return nil
		},
	}
	jwtSamlCmd.Flags().StringP("enc_key", "k", "", "Encryption key")
	jwtSamlCmd.Flags().StringP("salt", "s", "", "Salt for JWT base64 encoded (optional)")

	// jwt-api-token command
	jwtApiCmd := &cobra.Command{
		Use:   "jwt-api-token",
		Short: "Generate JWT secret for API token",
		RunE: func(cmd *cobra.Command, args []string) error {
			encKey, err := getRequiredString(cmd, "enc_key", "-k")
			if err != nil {
				return err
			}
			salt, err := getBase64Bytes(cmd, "salt", service.DefaultApiSalt)
			if err != nil {
				return err
			}

			encService := service.New([]byte(encKey))
			secret := encService.GetSecret(salt)

			// Output key data to stdout
			fmt.Println(base64.StdEncoding.EncodeToString(secret))
			return nil
		},
	}
	jwtApiCmd.Flags().StringP("enc_key", "k", "", "Encryption key")
	jwtApiCmd.Flags().StringP("salt", "s", "", "Salt for JWT base64 encoded (optional)")

	// get-secret command
	getSecretCmd := &cobra.Command{
		Use:   "get-secret",
		Short: "Get a secret using custom salt",
		RunE: func(cmd *cobra.Command, args []string) error {
			encKey, err := getRequiredString(cmd, "enc_key", "-k")
			if err != nil {
				return err
			}
			salt, err := getBase64Bytes(cmd, "salt", service.DefaultApiSalt)
			if err != nil {
				return err
			}

			encService := service.New([]byte(encKey))
			secret := encService.GetSecret(salt)

			// Output key data to stdout
			fmt.Println(base64.StdEncoding.EncodeToString(secret))
			return nil
		},
	}
	getSecretCmd.Flags().StringP("enc_key", "k", "", "Encryption key")
	getSecretCmd.Flags().StringP("salt", "s", "", "Salt for HMAC base64 encoded")

	rootCmd.AddCommand(decryptCmd, encryptCmd, jwtSamlCmd, jwtApiCmd, getSecretCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.Error("%v", err)
		os.Exit(1)
	}
}

func getBase64Bytes(cmd *cobra.Command, flagName string, defaultValue []byte) ([]byte, error) {
	str, err := cmd.Flags().GetString(flagName)
	if err != nil {
		return nil, err
	}
	if str == "" {
		return defaultValue, nil
	}
	return base64.StdEncoding.DecodeString(str)
}

func getOptionalString(cmd *cobra.Command, flagName, defaultValue string) (string, error) {
	str, err := cmd.Flags().GetString(flagName)
	if err != nil {
		return defaultValue, err
	}
	if str == "" {
		return defaultValue, nil
	}
	return str, nil
}

func getRequiredString(cmd *cobra.Command, flagName, shorthand string) (string, error) {
	str, err := cmd.Flags().GetString(flagName)
	if err != nil {
		return "", err
	}
	if str == "" {
		return "", fmt.Errorf("flag %s is required: %s", flagName, shorthand)
	}
	return str, nil
}

func getOptionalInt(cmd *cobra.Command, flagName string, defaultValue int) (int, error) {
	intVal, err := cmd.Flags().GetInt(flagName)
	if err != nil {
		return defaultValue, fmt.Errorf("error getting flag %s: %w", flagName, err)
	}
	if intVal == 0 {
		return defaultValue, nil
	}
	return intVal, nil
}
