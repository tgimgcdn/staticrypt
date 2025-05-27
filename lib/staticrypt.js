// Initialize the staticrypt module
const staticrypt = (function() {
    const exports = {};
    
    // Crypto engine implementation
    const cryptoEngine = (function() {
        const exports = {};
        const { subtle } = crypto;
        
        const IV_BITS = 16 * 8;
        const HEX_BITS = 4;
        const ENCRYPTION_ALGO = "AES-CBC";
        
        // Hex encoder/decoder
        const HexEncoder = {
            parse: function(hexString) {
                if (hexString.length % 2 !== 0) throw "Invalid hexString";
                const arrayBuffer = new Uint8Array(hexString.length / 2);
                for (let i = 0; i < hexString.length; i += 2) {
                    const byteValue = parseInt(hexString.substring(i, i + 2), 16);
                    if (isNaN(byteValue)) throw "Invalid hexString";
                    arrayBuffer[i / 2] = byteValue;
                }
                return arrayBuffer;
            },
            stringify: function(bytes) {
                return Array.from(bytes)
                    .map(b => b.toString(16).padStart(2, '0'))
                    .join('');
            }
        };
        
        // UTF8 encoder/decoder
        const UTF8Encoder = {
            parse: str => new TextEncoder().encode(str),
            stringify: bytes => new TextDecoder().decode(bytes)
        };
        
        // Encrypt function
        async function encrypt(msg, hashedPassword) {
            const iv = crypto.getRandomValues(new Uint8Array(IV_BITS / 8));
            const key = await subtle.importKey(
                "raw",
                HexEncoder.parse(hashedPassword),
                ENCRYPTION_ALGO,
                false,
                ["encrypt"]
            );
            
            const encrypted = await subtle.encrypt(
                { name: ENCRYPTION_ALGO, iv },
                key,
                UTF8Encoder.parse(msg)
            );
            
            return HexEncoder.stringify(iv) + HexEncoder.stringify(new Uint8Array(encrypted));
        }
        
        // Decrypt function
        async function decrypt(encryptedMsg, hashedPassword) {
            const ivLength = IV_BITS / HEX_BITS;
            const iv = HexEncoder.parse(encryptedMsg.substring(0, ivLength));
            const encrypted = encryptedMsg.substring(ivLength);
            
            const key = await subtle.importKey(
                "raw",
                HexEncoder.parse(hashedPassword),
                ENCRYPTION_ALGO,
                false,
                ["decrypt"]
            );
            
            const decrypted = await subtle.decrypt(
                { name: ENCRYPTION_ALGO, iv },
                key,
                HexEncoder.parse(encrypted)
            );
            
            return UTF8Encoder.stringify(new Uint8Array(decrypted));
        }
        
        // Hash password
        async function hashPassword(password, salt) {
            const key = await subtle.importKey(
                "raw",
                UTF8Encoder.parse(password),
                "PBKDF2",
                false,
                ["deriveBits"]
            );
            
            const keyBytes = await subtle.deriveBits(
                {
                    name: "PBKDF2",
                    hash: "SHA-256",
                    salt: UTF8Encoder.parse(salt),
                    iterations: 600000
                },
                key,
                256
            );
            
            return HexEncoder.stringify(new Uint8Array(keyBytes));
        }
        
        exports.encrypt = encrypt;
        exports.decrypt = decrypt;
        exports.hashPassword = hashPassword;
        return exports;
    })();

    // Initialize the module
    let decryptedContent = null;
    let currentPassword = null;
    
    // Initialize modal and event handlers
    function initializeModal() {
        const modal = document.getElementById('staticrypt-modal');
        if (!modal) return;

        const closeBtn = modal.querySelector('.staticrypt-modal-close');
        const form = modal.querySelector('#staticrypt-modal-form');
        const passwordInput = modal.querySelector('#staticrypt-modal-password');
        const toggleIcon = modal.querySelector('.staticrypt-toggle-password-visibility');

        // Close modal handlers
        closeBtn.onclick = () => modal.style.display = "none";
        window.onclick = (event) => {
            if (event.target == modal) modal.style.display = "none";
        };

        // Password visibility toggle
        toggleIcon.addEventListener("click", () => {
            if (passwordInput.type === "password") {
                passwordInput.type = "text";
                toggleIcon.alt = "隐藏密码";
                toggleIcon.title = "隐藏密码";
            } else {
                passwordInput.type = "password";
                toggleIcon.alt = "显示密码";
                toggleIcon.title = "显示密码";
            }
        });

        // Form submission
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = passwordInput.value;
            const rememberChecked = modal.querySelector('#staticrypt-modal-remember').checked;
            
            try {
                const hashedPassword = await cryptoEngine.hashPassword(password, window.staticryptConfig.salt);
                const decrypted = await cryptoEngine.decrypt(window.staticryptConfig.encryptedContent, hashedPassword);
                decryptedContent = JSON.parse(decrypted);
                currentPassword = hashedPassword;

                // Store password if remember is checked
                if (rememberChecked && window.staticryptConfig.isRememberEnabled) {
                    localStorage.setItem('staticrypt_passphrase', hashedPassword);
                    if (window.staticryptConfig.rememberDurationInDays > 0) {
                        localStorage.setItem(
                            'staticrypt_expiration',
                            (new Date().getTime() + window.staticryptConfig.rememberDurationInDays * 24 * 60 * 60 * 1000).toString()
                        );
                    }
                }

                // Decrypt the current section
                const sectionId = modal.dataset.currentSectionId;
                if (sectionId) {
                    const section = decryptedContent.find(s => s.id === sectionId);
                    if (section) {
                        const placeholder = document.querySelector(`[data-staticrypt-id="${sectionId}"]`);
                        if (placeholder) {
                            const temp = document.createElement('div');
                            temp.innerHTML = section.content;
                            while (temp.firstChild) {
                                placeholder.parentNode.insertBefore(temp.firstChild, placeholder);
                            }
                            placeholder.remove();
                        }
                    }
                }

                modal.style.display = "none";
                passwordInput.value = '';
            } catch (e) {
                alert('密码错误，请重试');
            }
        });
    }

    // Try to decrypt using remembered password
    async function tryRememberedPassword() {
        if (!window.staticryptConfig.isRememberEnabled) return false;

        const hashedPassword = localStorage.getItem('staticrypt_passphrase');
        const expiration = localStorage.getItem('staticrypt_expiration');
        
        if (!hashedPassword || (expiration && new Date().getTime() > parseInt(expiration))) {
            localStorage.removeItem('staticrypt_passphrase');
            localStorage.removeItem('staticrypt_expiration');
            return false;
        }

        try {
            const decrypted = await cryptoEngine.decrypt(window.staticryptConfig.encryptedContent, hashedPassword);
            decryptedContent = JSON.parse(decrypted);
            currentPassword = hashedPassword;

            // Decrypt all sections
            for (const section of decryptedContent) {
                const placeholder = document.querySelector(`[data-staticrypt-id="${section.id}"]`);
                if (placeholder) {
                    const temp = document.createElement('div');
                    temp.innerHTML = section.content;
                    while (temp.firstChild) {
                        placeholder.parentNode.insertBefore(temp.firstChild, placeholder);
                    }
                    placeholder.remove();
                }
            }
            return true;
        } catch (e) {
            localStorage.removeItem('staticrypt_passphrase');
            localStorage.removeItem('staticrypt_expiration');
            return false;
        }
    }

    // Initialize on DOMContentLoaded
    document.addEventListener('DOMContentLoaded', async function() {
        initializeModal();
        await tryRememberedPassword();
    });

    // Public API
    exports.decryptSection = function(sectionId) {
        if (decryptedContent && currentPassword) {
            const section = decryptedContent.find(s => s.id === sectionId);
            if (section) {
                const placeholder = document.querySelector(`[data-staticrypt-id="${sectionId}"]`);
                if (placeholder) {
                    const temp = document.createElement('div');
                    temp.innerHTML = section.content;
                    while (temp.firstChild) {
                        placeholder.parentNode.insertBefore(temp.firstChild, placeholder);
                    }
                    placeholder.remove();
                    return true;
                }
            }
        }
        return false;
    };

    exports.showPasswordPrompt = function(sectionId) {
        const modal = document.getElementById('staticrypt-modal');
        if (modal) {
            modal.dataset.currentSectionId = sectionId;
            modal.style.display = "block";
            modal.querySelector('#staticrypt-modal-password').focus();
        }
    };

    return exports;
})(); 
