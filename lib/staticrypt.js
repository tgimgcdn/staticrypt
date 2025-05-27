// 初始化静态加密模块
const staticrypt = (function() {
    const exports = {};
    const cryptoEngine = (function() {
        // ... 从 staticryptJs.js 复制 cryptoEngine 代码 ...
    })();
    const codec = (function() {
        // ... 从 staticryptJs.js 复制 codec 代码 ...
    })();

    // 初始化解密引擎
    const init = function(config) {
        const exports = {};

        // 解密并替换标记的内容
        async function decryptAndReplaceHtml(hashedPassword) {
            const result = await codec.decode(
                config.staticryptEncryptedMsgUniqueVariableName,
                hashedPassword,
                config.staticryptSaltUniqueVariableName
            );
            if (!result.success) {
                return false;
            }

            try {
                // 解析解密后的内容，它应该是一个包含加密部分的 JSON 字符串
                const encryptedSections = JSON.parse(result.decoded);
                
                // 只替换每个加密部分
                for (const section of encryptedSections) {
                    const { id, content } = section;
                    const placeholder = document.querySelector(`[data-staticrypt-id="${id}"]`);
                    if (placeholder) {
                        // 创建一个临时容器来解析 HTML 内容
                        const temp = document.createElement('div');
                        temp.innerHTML = content;
                        
                        // 用解密后的内容替换占位符
                        while (temp.firstChild) {
                            placeholder.parentNode.insertBefore(temp.firstChild, placeholder);
                        }
                        placeholder.remove();
                    }
                }
                return true;
            } catch (e) {
                console.error('Failed to parse decrypted content:', e);
                return false;
            }
        }

        // 处理密码解密
        async function handleDecryptionOfPage(password, isRememberChecked) {
            const hashedPassword = await cryptoEngine.hashPassword(password, config.staticryptSaltUniqueVariableName);
            const isSuccessful = await decryptAndReplaceHtml(hashedPassword);

            if (isSuccessful && isRememberChecked && config.isRememberEnabled) {
                localStorage.setItem('staticrypt_passphrase', hashedPassword);
                if (config.rememberDurationInDays > 0) {
                    localStorage.setItem(
                        'staticrypt_expiration',
                        (new Date().getTime() + config.rememberDurationInDays * 24 * 60 * 60 * 1000).toString()
                    );
                }
            }

            return { isSuccessful };
        }

        // 显示密码提示框
        function showPasswordPrompt(sectionId) {
            const modal = document.getElementById('staticrypt-modal');
            if (modal) {
                modal.style.display = "block";
                document.getElementById('staticrypt-modal-password').focus();
                modal.dataset.currentSectionId = sectionId;
            }
        }

        exports.handleDecryptionOfPage = handleDecryptionOfPage;
        exports.showPasswordPrompt = showPasswordPrompt;
        return exports;
    };

    // 初始化模块
    if (window.staticryptConfig) {
        const staticryptInstance = init(window.staticryptConfig);
        Object.assign(exports, staticryptInstance);
    }

    return exports;
})();

// 添加密码提示框到页面
document.addEventListener('DOMContentLoaded', function() {
    const modalHtml = `
        <div id="staticrypt-modal" class="staticrypt-modal">
            <div class="staticrypt-modal-content">
                <span class="staticrypt-modal-close">&times;</span>
                <div class="staticrypt-form">
                    <div class="staticrypt-instructions">
                        <p class="staticrypt-title">密码保护</p>
                        <p>请输入密码以查看受保护的内容</p>
                    </div>
                    <hr class="staticrypt-hr" />
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
                                src="data:image/svg+xml;base64,..."
                            />
                        </div>
                        <label id="staticrypt-modal-remember-label" class="staticrypt-remember">
                            <input id="staticrypt-modal-remember" type="checkbox" name="remember" />
                            记住密码
                        </label>
                        <input type="submit" class="staticrypt-decrypt-button" value="解密" />
                    </form>
                </div>
            </div>
        </div>
    `;

    // 添加模态框到页面
    document.body.insertAdjacentHTML('beforeend', modalHtml);

    // 添加模态框功能
    const modal = document.getElementById('staticrypt-modal');
    const closeBtn = modal.querySelector('.staticrypt-modal-close');

    closeBtn.onclick = function() {
        modal.style.display = "none";
    }

    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    }

    // 处理密码表单提交
    document.getElementById('staticrypt-modal-form').addEventListener('submit', async function(e) {
        e.preventDefault();

        const password = document.getElementById('staticrypt-modal-password').value;
        const isRememberChecked = document.getElementById('staticrypt-modal-remember').checked;

        const { isSuccessful } = await staticrypt.handleDecryptionOfPage(password, isRememberChecked);

        if (isSuccessful) {
            modal.style.display = "none";
        } else {
            alert("密码错误，请重试");
        }
    });

    // 添加密码可见性切换功能
    const toggleIcon = modal.querySelector(".staticrypt-toggle-password-visibility");
    toggleIcon.addEventListener("click", function() {
        const passwordInput = document.getElementById("staticrypt-modal-password");
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
}); 
