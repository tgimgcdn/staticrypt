#!/usr/bin/env node

"use strict";

// check node version before anything else
const nodeVersion = process.versions.node.split(".");
if (nodeVersion[0] < 16) {
    console.log("ERROR: Node version 16 or higher is required.");
    process.exit(1);
}

// parse .env file into process.env
require("dotenv").config();

const pathModule = require("path");
const fs = require("fs");

const cryptoEngine = require("../lib/cryptoEngine.js");
const codec = require("../lib/codec.js");
const { generateRandomSalt } = cryptoEngine;
const { decode, encodeWithHashedPassword } = codec.init(cryptoEngine);
const {
    OUTPUT_DIRECTORY_DEFAULT_PATH,
    buildStaticryptJS,
    exitWithError,
    genFile,
    getConfig,
    getFileContent,
    getPassword,
    getValidatedSalt,
    isOptionSetByUser,
    parseCommandLineArguments,
    recursivelyApplyCallbackToHtmlFiles,
    validatePassword,
    writeConfig,
    writeFile,
    getFullOutputPath,
} = require("./helpers.js");

// parse arguments
const yargs = parseCommandLineArguments();
const namedArgs = yargs.argv;

async function runStatiCrypt() {
    const hasSaltFlag = isOptionSetByUser("s", yargs);
    const hasShareFlag = isOptionSetByUser("share", yargs);

    const positionalArguments = namedArgs._;

    // require at least one positional argument unless some specific flags are passed
    if (!hasShareFlag && !(hasSaltFlag && !namedArgs.salt)) {
        if (positionalArguments.length === 0) {
            console.log("ERROR: Invalid number of arguments. Please provide an input file.\n");

            yargs.showHelp();
            process.exit(1);
        }
    }

    // get config file
    const configPath = namedArgs.config.toLowerCase() === "false" ? null : "./" + namedArgs.config;
    const config = getConfig(configPath);

    // if the 's' flag is passed without parameter, generate a salt, display & exit
    if (hasSaltFlag && !namedArgs.salt) {
        const generatedSalt = generateRandomSalt();

        // show salt
        console.log(generatedSalt);

        // write to config file if it doesn't exist
        if (!config.salt) {
            config.salt = generatedSalt;
            writeConfig(configPath, config);
        }

        return;
    }

    // get the salt & password
    const salt = getValidatedSalt(namedArgs, config);
    const password = await getPassword(namedArgs.password);
    const hashedPassword = await cryptoEngine.hashPassword(password, salt);

    // display the share link with the hashed password if the --share flag is set
    if (hasShareFlag) {
        await validatePassword(password, namedArgs.short);

        let url = namedArgs.share || "";
        url += "#staticrypt_pwd=" + hashedPassword;

        if (namedArgs.shareRemember) {
            url += `&remember_me`;
        }

        console.log(url);
        return;
    }

    // only process a directory if the --recursive flag is set
    const directoriesInArguments = positionalArguments.filter((path) => fs.statSync(path).isDirectory());
    if (directoriesInArguments.length > 0 && !namedArgs.recursive) {
        exitWithError(
            `'${directoriesInArguments[0].toString()}' is a directory. Use the -r|--recursive flag to process directories.`
        );
    }

    // if asking for decryption, decrypt all the files
    if (namedArgs.decrypt) {
        const isOutputDirectoryDefault =
            namedArgs.directory === OUTPUT_DIRECTORY_DEFAULT_PATH && !isOptionSetByUser("d", yargs);
        const outputDirectory = isOutputDirectoryDefault ? "decrypted" : namedArgs.directory;

        positionalArguments.forEach((path) => {
            recursivelyApplyCallbackToHtmlFiles(
                (fullPath, fullRootDirectory) => {
                    decodeAndGenerateFile(fullPath, fullRootDirectory, hashedPassword, outputDirectory);
                },
                path,
                namedArgs.directory
            );
        });

        return;
    }

    await validatePassword(password, namedArgs.short);

    // write salt to config file
    if (config.salt !== salt) {
        config.salt = salt;
        writeConfig(configPath, config);
    }

    const isRememberEnabled = namedArgs.remember !== "false";

    const baseTemplateData = {
        is_remember_enabled: JSON.stringify(isRememberEnabled),
        js_staticrypt: buildStaticryptJS(),
        template_button: namedArgs.templateButton,
        template_color_primary: namedArgs.templateColorPrimary,
        template_color_secondary: namedArgs.templateColorSecondary,
        template_error: namedArgs.templateError,
        template_instructions: namedArgs.templateInstructions,
        template_placeholder: namedArgs.templatePlaceholder,
        template_remember: namedArgs.templateRemember,
        template_title: namedArgs.templateTitle,
        template_toggle_show: namedArgs.templateToggleShow,
        template_toggle_hide: namedArgs.templateToggleHide,
    };

    // encode all the files
    positionalArguments.forEach((path) => {
        recursivelyApplyCallbackToHtmlFiles(
            (fullPath, fullRootDirectory) => {
                encodeAndGenerateFile(
                    fullPath,
                    fullRootDirectory,
                    hashedPassword,
                    salt,
                    baseTemplateData,
                    isRememberEnabled,
                    namedArgs
                );
            },
            path,
            namedArgs.directory
        );
    });
}

async function decodeAndGenerateFile(path, fullRootDirectory, hashedPassword, outputDirectory) {
    // get the file content
    const encryptedFileContent = getFileContent(path);

    // extract the cipher text from the encrypted file
    const cipherTextMatch = encryptedFileContent.match(/"staticryptEncryptedMsgUniqueVariableName":\s*"([^"]+)"/);
    const saltMatch = encryptedFileContent.match(/"staticryptSaltUniqueVariableName":\s*"([^"]+)"/);

    if (!cipherTextMatch || !saltMatch) {
        return console.log(`ERROR: could not extract cipher text or salt from ${path}`);
    }

    // decrypt input
    const { success, decoded } = await decode(cipherTextMatch[1], hashedPassword, saltMatch[1]);

    if (!success) {
        return console.log(`ERROR: could not decrypt ${path}`);
    }

    const outputFilepath = getFullOutputPath(path, fullRootDirectory, outputDirectory);

    writeFile(outputFilepath, decoded);
}

/**
 * Process HTML content to extract and encrypt marked sections
 * @param {string} htmlContent - The original HTML content
 * @returns {Object} { encryptedContent: string, processedHtml: string }
 */
function processHtmlContent(htmlContent) {
    const encryptedSections = [];
    let sectionId = 0;
    
    // Replace marked content with placeholders and collect content to encrypt
    const processedHtml = htmlContent.replace(
        /<!--staticrypt-start-->([\s\S]*?)<!--staticrypt-end-->/g,
        (match, content) => {
            const id = `staticrypt-section-${sectionId++}`;
            encryptedSections.push({ id, content: content.trim() });
            
            // Return a placeholder that will be replaced with decrypted content
            return `<div class="staticrypt-encrypted" data-staticrypt-id="${id}">
                <div class="staticrypt-placeholder">
                    <div class="staticrypt-password-prompt">
                        <p>此内容受密码保护</p>
                        <button onclick="staticrypt.showPasswordPrompt('${id}')">点击查看内容</button>
                    </div>
                </div>
            </div>`;
        }
    );

    return {
        encryptedContent: JSON.stringify(encryptedSections),
        processedHtml
    };
}

async function encodeAndGenerateFile(
    path,
    rootDirectoryFromArguments,
    hashedPassword,
    salt,
    baseTemplateData,
    isRememberEnabled,
    namedArgs
) {
    // Get file content
    const contents = getFileContent(path);

    // Process HTML content to extract and encrypt marked sections
    const { encryptedContent, processedHtml } = processHtmlContent(contents);

    // If no marked content found, just copy the file
    if (encryptedContent === '[]') {
        const relativePath = pathModule.relative(rootDirectoryFromArguments, path);
        const outputFilepath = namedArgs.directory + "/" + relativePath;
        writeFile(outputFilepath, contents);
        return;
    }

    // Encrypt the marked content
    const encryptedMsg = await encodeWithHashedPassword(encryptedContent, hashedPassword);

    let rememberDurationInDays = parseInt(namedArgs.remember);
    rememberDurationInDays = isNaN(rememberDurationInDays) ? 0 : rememberDurationInDays;

    // Inject encryption config and scripts into the HTML
    const injectedHtml = processedHtml.replace('</head>', `
        <script>
            window.staticryptConfig = {
                encryptedContent: "${encryptedMsg}",
                salt: "${salt}",
                isRememberEnabled: ${isRememberEnabled},
                rememberDurationInDays: ${rememberDurationInDays}
            };
        </script>
        <script src="staticrypt.js"></script>
        <style>
            .staticrypt-encrypted {
                margin: 1em 0;
            }
            .staticrypt-placeholder {
                background: #f5f5f5;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 20px;
                text-align: center;
            }
            .staticrypt-password-prompt {
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 10px;
            }
            .staticrypt-password-prompt button {
                background: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 14px;
            }
            .staticrypt-password-prompt button:hover {
                filter: brightness(92%);
            }
            .staticrypt-modal {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.5);
                z-index: 1000;
            }
            .staticrypt-modal-content {
                position: relative;
                background: white;
                margin: 15% auto;
                padding: 20px;
                width: 80%;
                max-width: 500px;
                border-radius: 4px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            }
            .staticrypt-modal-close {
                position: absolute;
                right: 10px;
                top: 10px;
                font-size: 20px;
                cursor: pointer;
                color: #666;
            }
            .staticrypt-form {
                padding: 20px;
            }
            .staticrypt-instructions {
                margin-bottom: 20px;
                text-align: center;
            }
            .staticrypt-title {
                font-size: 1.5em;
                margin-bottom: 10px;
            }
            .staticrypt-password-container {
                position: relative;
                margin-bottom: 15px;
            }
            .staticrypt-password-container input {
                width: 100%;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 14px;
            }
            .staticrypt-remember {
                display: flex;
                align-items: center;
                margin-bottom: 15px;
                justify-content: center;
            }
            .staticrypt-remember input {
                margin-right: 8px;
            }
            .staticrypt-decrypt-button {
                background: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 14px;
                width: 100%;
            }
            .staticrypt-decrypt-button:hover {
                filter: brightness(92%);
            }
        </style>
    </head>`);

    // Add password modal
    const modalHtml = `
        <div id="staticrypt-modal" class="staticrypt-modal">
            <div class="staticrypt-modal-content">
                <span class="staticrypt-modal-close">&times;</span>
                <div class="staticrypt-form">
                    <div class="staticrypt-instructions">
                        <p class="staticrypt-title">密码保护</p>
                        <p>请输入密码以查看受保护的内容</p>
                    </div>
                    <form id="staticrypt-modal-form" action="#" method="post">
                        <div class="staticrypt-password-container">
                            <input
                                id="staticrypt-modal-password"
                                type="password"
                                name="password"
                                placeholder="请输入密码"
                                autofocus
                            />
                            <img
                                class="staticrypt-toggle-password-visibility"
                                alt="显示密码"
                                title="显示密码"
                                src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NDAgNTEyIj48IS0tIUZvbnQgQXdlc29tZSBGcmVlIDYuNS4yIGJ5IEBmb250YXdlc29tZSAtIGh0dHBzOi8vZm9udGF3ZXNvbWUuY29tIExpY2Vuc2UgLSBodHRwczovL2ZvbnRhd2Vzb21lLmNvbS9saWNlbnNlL2ZyZWUgQ29weXJpZ2h0IDIwMjQgRm9udGljb25zLCBJbmMuLS0+PHBhdGggZD0iTTM4LjggNS4xQzI4LjQtMy4xIDEzLjMtMS4yIDUuMSA5LjJTLTEuMiAzNC43IDkuMiA0Mi45bDU5MiA0NjRjMTAuNCA4LjIgMjUuNSA2LjMgMzMuNy00LjFzNi4zLTI1LjUtNC4xLTMzLjdMNTI1LjYgMzg2LjdjMzkuNi00MC42IDY2LjQtODYuMSA3OS45LTExOC40YzMuMy03LjkgMy4zLTE2LjcgMC0yNC42Yy0xNC45LTM1LjctNDYuMi04Ny43LTkzLTEzMS4xQzQ2NS41IDY4LjggNDAwLjggMzIgMzIwIDMyYy02OC4yIDAtMTI1IDI2LjMtMTY5LjMgNjAuOEwzOC44IDUuMXpNMjIzLjEgMTQ5LjVDMjQ4LjYgMTI2LjIgMjgyLjcgMTEyIDMyMCAxMTJjNzkuNSAwIDE0NCA2NC41IDE0NCAxNDRjMCAyNC45LTYuMyA0OC4zLTE3LjQgNjguN0w0MDggMjk0LjVjOC40LTE5LjMgMTAuNi00MS40IDQuOC02My4zYy0xMS4xLTQxLjUtNDcuOC02OS40LTg4LjYtNzEuMWMtNS44LS4yLTkuMiA2LjEtNy40IDExLjdjMi4xIDYuNCAzLjMgMTMuMiAzLjMgMjAuM2MwIDEwLjItMi40IDE5LjgtNi42IDI4LjNsLTkwLjMtNzAuOHpNMzczIDM4OS45Yy0xNi40IDYuNS0zNC4zIDEwLjEtNTMgMTAuMWMtNzkuNSAwLTE0NC02NC41LTE0NC0xNDRjMC02LjkgLjUtMTMuNiAxLjQtMjAuMkw4My4xIDE2MS41QzYwLjMgMTkxLjIgNDQgMjIwLjggMzQuNSAyNDMuN2MtMy4zIDcuOS0zLjMgMTYuNyAwIDI0LjZjMTQuOSAzNS43IDQ2LjIgODcuNyA5MyAxMzEuMUMxNzQuNSA0NDMuMiAyMzkuMiA0ODAgMzIwIDQ4MGM0Ny44IDAgODkuOS0xMi45IDEyNi4yLTMyLjVMMzczIDM4OS45eiIvPjwvc3ZnPg=="
                            />
                        </div>
                        <label class="staticrypt-remember">
                            <input id="staticrypt-modal-remember" type="checkbox" name="remember" />
                            记住密码
                        </label>
                        <input type="submit" class="staticrypt-decrypt-button" value="解密" />
                    </form>
                </div>
            </div>
        </div>
    `;

    const finalHtml = injectedHtml.replace('</body>', `${modalHtml}</body>`);

    // Write the processed file
    const relativePath = pathModule.relative(rootDirectoryFromArguments, path);
    const outputFilepath = namedArgs.directory + "/" + relativePath;
    writeFile(outputFilepath, finalHtml);
}

runStatiCrypt();
