# ProtectKit

ProtectKit é um framework para gerenciamento de criptografia e chaves em aplicativos Swift. Ele oferece funcionalidades avançadas como geração de chaves RSA, criptografia e descriptografia de dados, exportação e importação de chaves em formato PEM, e muito mais.

## Funcionalidades

- **Geração e Armazenamento de Chaves RSA**
- **Criptografia e Descriptografia de Dados**
- **Exportação e Importação de Chaves em PEM**
- **Geração de Hashes e Comparação de Senhas**
- **Geração e Validação de Tokens e OTPs**
- **Armazenamento Seguro de Dados**

 ## Uso

Para começar a usar o ProtectKit, adicione o framework ao seu projeto usando o Swift Package Manager:

1. No Xcode, vá para File > Swift Packages > Add Package Dependency.
2. Insira a URL do repositório GitHub: https://github.com/yourusername/ProtectKit.git.
3. Selecione a versão desejada e adicione o pacote ao seu projeto.

### Exemplos de Código

#### Gerar Chaves RSA


import ProtectKit

let keys = ProtectKit.generateRSAKeyPair(tag: "myKeyTag")
let privateKey = keys.privateKey
let publicKey = keys.publicKey
