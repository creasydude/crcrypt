#!/usr/bin/env node

import { encrypt, decrypt } from './utils/crypto.js';
import {
    loadDataFromJsonFile,
    saveDataToJsonFile,
    doesConfigFileExist
} from './utils/config.js';
import {
    select,
    input,
    password,
    confirm
} from '@inquirer/prompts';
import showHeader from "./utils/header.js";
import chalk from "chalk";

class EncryptionApp {
    constructor() {
        this.configPath = 'config';
        this.configFile = 'config.json';
        this.settings = {
            algorithm: null,
            saltLength: null,
            ivLength: null,
            keyLength: null,
            iterations: null
        };
        this.mode = null;
        this.data = null;
        this.passwordString = null;
    }

    async run() {
        try {
            await showHeader();
            await this.selectMode();
            await this.loadOrSetupSettings();
            await this.processData();
            await this.promptBackToMainMenu();
        } catch (error) {
            this.handleError(error);
        }
    }

    async selectMode() {
        this.mode = await select({
            message: 'Pick the mode:',
            choices: [
                {
                    name: 'Encrypt',
                    value: 'encrypt',
                    description: 'Encrypt your chosen data text with a selected password.',
                },
                {
                    name: 'Decrypt',
                    value: 'decrypt',
                    description: 'Decrypt your encrypted text using the selected password.',
                },
            ],
        });
    }

    async loadOrSetupSettings() {
        const configExists = doesConfigFileExist(this.configPath, this.configFile);

        if (configExists) {
            await this.loadExistingSettings();
        } else {
            await this.setupNewSettings();
        }
    }

    async loadExistingSettings() {
        try {
            const loadedData = await loadDataFromJsonFile(this.configPath, this.configFile);
            this.displayPreviousSettings(loadedData);

            const shouldLoadConfig = await confirm({
                message: 'We found previous settings. Would you like to load them?',
                default: true,
            });

            if (shouldLoadConfig) {
                this.settings = {
                    algorithm: loadedData.algorithm,
                    saltLength: loadedData.saltLength,
                    ivLength: loadedData.ivLength,
                    keyLength: loadedData.keyLength,
                    iterations: loadedData.iterations
                };
            } else {
                await this.setupNewSettings();
            }
        } catch (error) {
            this.handleError(error);
        }
    }

    displayPreviousSettings(loadedData) {
        console.log(chalk.bold('⚙️ Previous Settings:'));
        const settings = [
            { name: 'Algorithm', value: loadedData?.algorithm },
            { name: 'Salt Length', value: loadedData?.saltLength },
            { name: 'IV Length', value: loadedData?.ivLength },
            { name: 'Key Length', value: loadedData?.keyLength },
            { name: 'Iterations', value: loadedData?.iterations },
        ];
        settings.forEach(setting =>
            console.log(chalk.gray(`ℹ️ ${setting.name}: ${setting.value}`))
        );
    }

    async setupNewSettings() {
        this.settings.algorithm = await this.selectAlgorithm();
        this.settings.saltLength = await this.inputNumericSetting('Salt Length', 32);
        this.settings.ivLength = await this.inputNumericSetting('IV Length', 16);
        this.settings.keyLength = await this.inputNumericSetting('Key Length', 32);
        this.settings.iterations = await this.inputNumericSetting('Iterations Length', 100000);

        await this.saveSettings();
    }

    async selectAlgorithm() {
        return select({
            message: 'Choose an AES algorithm:',
            choices: [
                { name: 'AES-256-CBC (Recommended)', value: 'aes-256-cbc', description: "Recommended option" },
                { name: 'AES-256-GCM', value: 'aes-256-gcm' },
                { name: 'AES-128-GCM', value: 'aes-128-gcm' },
                { name: 'AES-128-CBC', value: 'aes-128-cbc' },
                { name: 'AES-192-CBC', value: 'aes-192-cbc' },
                { name: 'AES-192-GCM', value: 'aes-192-gcm' }
            ],
            default: 'aes-256-cbc',
            required: true
        });
    }

    async inputNumericSetting(name, defaultValue) {
        return input({
            message: `Choose the ${name}:`,
            default: defaultValue,
            required: true,
            validate: this.validateNumericInput
        });
    }

    validateNumericInput(input) {
        const num = parseInt(input, 10);
        if (isNaN(num)) {
            return 'Please enter a valid number.';
        }
        if (num <= 0) {
            return 'Please enter a number greater than zero.';
        }
        return true;
    }

    async saveSettings() {
        try {
            await saveDataToJsonFile(
                this.configPath,
                this.configFile,
                this.settings
            );
            console.log(chalk.bgGreen(chalk.white(`Settings saved. Now it's time to ${this.mode}.`)));
        } catch (error) {
            this.handleError(error);
        }
    }

    async processData() {
        if (this.mode === 'encrypt') {
            await this.encryptData();
        } else if (this.mode === 'decrypt') {
            await this.decryptData();
        }
    }

    async encryptData() {
        console.log(chalk.bgBlueBright(chalk.bold("\nENCRYPT")));

        this.data = await this.validateInput('Enter the data string you want to encrypt:');
        console.log(chalk.yellow("📌 Recommended: Use a secret password of 12-16 characters with uppercase, lowercase, numbers, and special characters."));

        this.passwordString = await this.getAndConfirmPassword();

        try {
            const encrypted = encrypt(
                this.passwordString,
                this.data,
                Number(this.settings.saltLength),
                Number(this.settings.ivLength),
                String(this.settings.algorithm),
                Number(this.settings.iterations),
                Number(this.settings.keyLength)
            );

            this.displayResult('🔒 Encrypted String', encrypted);
        } catch (error) {
            this.handleError(error);
        }
    }

    async decryptData() {
        console.log(chalk.bgBlueBright(chalk.bold("\nDECRYPT")));

        this.data = await this.validateInput('Enter the encrypted string you want to decrypt:');
        this.passwordString = await this.validateInput('Enter the password:', true);

        try {
            const decrypted = decrypt(
                this.passwordString,
                this.data,
                String(this.settings.algorithm),
                Number(this.settings.iterations),
                Number(this.settings.keyLength)
            );

            this.displayResult('🔒 Decrypted String', decrypted);
        } catch (error) {
            this.handleDecryptionError(error);
        }
    }

    async validateInput(message, isPassword = false) {
        return isPassword
            ? await password({
                message,
                mask: true,
                validate: input => input.trim() === ""
                    ? "Field can't be empty"
                    : true
            })
            : await input({
                message,
                validate: input => input.trim() === ""
                    ? "Field can't be empty"
                    : true
            });
    }

    async getAndConfirmPassword() {
        const passwordString = await this.validateInput('Enter the password:', true);

        await password({
            message: 'Re-Enter the password:',
            mask: true,
            validate: input => input !== passwordString
                ? 'Passwords Must Be The Same'
                : true
        });

        return passwordString;
    }

    displayResult(label, data) {
        console.log(chalk.magenta("\n======"));
        console.log(chalk.bold(`${label} : ` + chalk.cyan(data)));
        console.log(chalk.magenta("======"));
        console.log(chalk.bold('🔑 Password Used : ' + chalk.gray(this.passwordString)));
        console.log(chalk.magenta("======\n"));
    }

    async promptBackToMainMenu() {
        const backToMenu = await confirm({
            message: "Would you like to go back to the main menu?",
            default: true
        });

        if (backToMenu) {
            await this.run();
        }
    }

    handleDecryptionError(error) {
        if (String(error).includes("1C800064")) {
            console.log(chalk.bgRed("⚠️ Wrong Password"));
        } else {
            this.handleError(error);
        }
    }

    handleError(error) {
        console.error(chalk.bgRed(`⚠️ ${error.message}`));
    }
}

async function main() {
    const app = new EncryptionApp();
    await app.run();
}

main().catch(console.error);