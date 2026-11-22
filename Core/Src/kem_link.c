/**
  ******************************************************************************
  * @file    kem_link.c
  * @brief   Post-quantum secure link STM32 <-> PC ("qlink v1").
  *
  *  KEM      : ML-KEM-768, PQClean "clean" (built with PQC_OPT_LEVEL, -Os)
  *  KDF      : HKDF-SHA256 (ST CMOX)
  *  AEAD     : AES-256-GCM, 16 B tag (ST CMOX)
  *  Transport: USART2 / ST-LINK VCP 115200 8N1 (port_read/port_write below are
  *             the only transport-specific functions -> Ethernet later)
  *
  *  Frame:  A5 5A | type (1) | len (2, LE) | payload (len) | CRC-16 (2, LE)
  *          CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) over type|len|payload
  *
  *  Types:
  *   0x01 HELLO      PC->MCU  ver(1)=1 | role(1) | pc_nonce(16)
  *                            role 0: PC generates the key pair, MCU encapsulates
  *                            role 1: MCU generates the key pair, PC encapsulates
  *   0x81 HELLO_ACK  MCU->PC  ver(1) | role(1) | mcu_nonce(16) | "ML-KEM-768/..." (ASCII)
  *   0x02 PK         key-pair owner -> peer, ML-KEM-768 encapsulation key (1184 B)
  *   0x03 CT         peer -> key-pair owner, ML-KEM-768 ciphertext (1088 B)
  *   0x10 DATA       both     seq(8, LE) | AES-GCM ciphertext | tag(16)
  *   0x20 STAT       MCU->PC  ASCII "key=value ..." (timings in CPU cycles)
  *   0x7F ERR        MCU->PC  ASCII error text
  *
  *  Handshake role 0:  HELLO -> HELLO_ACK -> PK(PC) -> CT(MCU) + STAT + DATA(confirm)
  *  Handshake role 1:  HELLO -> HELLO_ACK + PK(MCU) -> CT(PC) -> STAT + DATA(confirm)
  *  A new HELLO at any time starts a new session (re-keying).
  *
  *  Session keys:  th  = SHA-256(pk || ct)
  *                 okm = HKDF-SHA256(ikm = ss, salt = th, info = "qlink-v1 aes-256-gcm", 64 B)
  *                 k_pc2mcu = okm[0..31], k_mcu2pc = okm[32..63]
  *  DATA nonce:    dir(4, BE: 1 = PC->MCU, 2 = MCU->PC) || seq(8, LE), seq starts at 1
  *                 and must strictly increase (replay protection).
  *  DATA AAD:      type (0x10) || seq(8, LE)
  *
  *  Security notes (for the thesis): there is no authentication of the peers
  *  (no signatures / certificates), so the link is protected against passive
  *  eavesdropping, including a future quantum adversary, but not against an
  *  active man-in-the-middle. Adding ML-DSA signatures would fix that.
  *  STM32F446 has no TRNG - see pqc_rng.c.
  ******************************************************************************
  */
#include <stdio.h>
#include <string.h>

#include "main.h"
#include "usart.h"
#include "kem_link.h"

#include "cmox_crypto.h"
#include "randombytes.h"
#include "ml-kem-768/clean/api.h"

#ifndef PQC_OPT_LEVEL_STR
#define PQC_OPT_LEVEL_STR "?"
#endif

/* ------------------------------------------------------------------------ */
#define QL_VERSION        1u
#define QL_SYNC0          0xA5u
#define QL_SYNC1          0x5Au
#define QL_MAX_PAYLOAD    2048u
#define QL_MAX_PLAINTEXT  1024u
#define QL_TAG_LEN        16u

#define QL_T_HELLO        0x01u
#define QL_T_HELLO_ACK    0x81u
#define QL_T_PK           0x02u
#define QL_T_CT           0x03u
#define QL_T_DATA         0x10u
#define QL_T_STAT         0x20u
#define QL_T_ERR          0x7Fu

#define QL_ROLE_PC_KEYGEN   0u
#define QL_ROLE_MCU_KEYGEN  1u

#define PK_LEN  PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES   /* 1184 */
#define SK_LEN  PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES   /* 2400 */
#define CT_LEN  PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES  /* 1088 */
#define SS_LEN  PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES            /* 32 */

static const char QL_ALG_NAME[] = "ML-KEM-768/PQClean " PQC_OPT_LEVEL_STR " + HKDF-SHA256 + AES-256-GCM (CMOX)";
static const char QL_KDF_INFO[] = "qlink-v1 aes-256-gcm";

/* ------------------------------------------------------------------------ */
static uint8_t rx_buf[QL_MAX_PAYLOAD + 8u];
static uint8_t tx_buf[QL_MAX_PAYLOAD + 8u];

static uint8_t pk[PK_LEN];
static uint8_t sk[SK_LEN];
static uint8_t ct[CT_LEN];
static uint8_t ss[SS_LEN];
static uint8_t transcript[PK_LEN + CT_LEN];
static uint8_t k_pc2mcu[32];
static uint8_t k_mcu2pc[32];

static uint8_t  role;
static int      waiting_for;        /* QL_T_PK or QL_T_CT or 0 */
static int      session_ok;
static uint64_t seq_tx;
static uint64_t seq_rx_last;

static uint32_t last_kem_cycles, last_kdf_cycles;
static uint32_t msgs_rx, msgs_tx, auth_fail;

/* ======================================================================== */
/* Transport (USART2). Replace these two functions for another interface.   */
/* ======================================================================== */
static int port_read(uint8_t *buf, uint16_t n, uint32_t timeout_ms)
{
  if (__HAL_UART_GET_FLAG(&huart2, UART_FLAG_ORE))
  {
    __HAL_UART_CLEAR_OREFLAG(&huart2);
  }
  return (HAL_UART_Receive(&huart2, buf, n, timeout_ms) == HAL_OK) ? 0 : -1;
}

static void port_write(const uint8_t *buf, uint16_t n)
{
  (void)HAL_UART_Transmit(&huart2, buf, n, HAL_MAX_DELAY);
}

/* ======================================================================== */
/* Framing                                                                   */
/* ======================================================================== */
static uint16_t crc16_ccitt(const uint8_t *d, size_t n, uint16_t crc)
{
  while (n--)
  {
    crc ^= (uint16_t)(*d++) << 8;
    for (int i = 0; i < 8; i++)
    {
      crc = (crc & 0x8000u) ? (uint16_t)((crc << 1) ^ 0x1021u) : (uint16_t)(crc << 1);
    }
  }
  return crc;
}

static void frame_send(uint8_t type, const uint8_t *payload, uint16_t len)
{
  tx_buf[0] = QL_SYNC0;
  tx_buf[1] = QL_SYNC1;
  tx_buf[2] = type;
  tx_buf[3] = (uint8_t)(len & 0xFFu);
  tx_buf[4] = (uint8_t)(len >> 8);
  if (len != 0u && payload != &tx_buf[5])
  {
    memcpy(&tx_buf[5], payload, len);
  }
  uint16_t crc = crc16_ccitt(&tx_buf[2], 3u + len, 0xFFFFu);
  tx_buf[5u + len] = (uint8_t)(crc & 0xFFu);
  tx_buf[6u + len] = (uint8_t)(crc >> 8);
  port_write(tx_buf, (uint16_t)(7u + len));
}

static void send_text(uint8_t type, const char *fmt_text)
{
  frame_send(type, (const uint8_t *)fmt_text, (uint16_t)strlen(fmt_text));
}

/* Blocking receive of one valid frame. Returns payload length, type in *type. */
static uint16_t frame_recv(uint8_t *type)
{
  for (;;)
  {
    uint8_t b;
    if (port_read(&b, 1u, HAL_MAX_DELAY) != 0 || b != QL_SYNC0)
    {
      continue;
    }
    uint32_t t_sync = DWT->CYCCNT;
    if (port_read(&b, 1u, 100u) != 0 || b != QL_SYNC1)
    {
      continue;
    }
    uint8_t hdr[3];
    if (port_read(hdr, 3u, 100u) != 0)
    {
      continue;
    }
    uint16_t len = (uint16_t)(hdr[1] | ((uint16_t)hdr[2] << 8));
    if (len > QL_MAX_PAYLOAD)
    {
      continue;
    }
    if (port_read(rx_buf, (uint16_t)(len + 2u), 2000u) != 0)
    {
      continue;
    }
    uint16_t crc = crc16_ccitt(hdr, 3u, 0xFFFFu);
    crc = crc16_ccitt(rx_buf, len, crc);
    if (crc != (uint16_t)(rx_buf[len] | ((uint16_t)rx_buf[len + 1u] << 8)))
    {
      send_text(QL_T_ERR, "bad crc");
      continue;
    }
    /* timing jitter of the USB/UART link -> RNG seed (weak, see pqc_rng.c) */
    uint32_t jitter[2] = { t_sync, DWT->CYCCNT };
    pqc_rng_mix((const uint8_t *)jitter, sizeof(jitter));
    *type = hdr[0];
    return len;
  }
}

/* ======================================================================== */
/* Crypto helpers                                                            */
/* ======================================================================== */
static void put_le64(uint8_t *p, uint64_t v)
{
  for (int i = 0; i < 8; i++)
  {
    p[i] = (uint8_t)(v >> (8 * i));
  }
}

static uint64_t get_le64(const uint8_t *p)
{
  uint64_t v = 0u;
  for (int i = 7; i >= 0; i--)
  {
    v = (v << 8) | p[i];
  }
  return v;
}

static void make_nonce(uint8_t nonce[12], uint32_t dir, uint64_t seq)
{
  nonce[0] = (uint8_t)(dir >> 24);
  nonce[1] = (uint8_t)(dir >> 16);
  nonce[2] = (uint8_t)(dir >> 8);
  nonce[3] = (uint8_t)(dir);
  put_le64(&nonce[4], seq);
}

static int derive_session_keys(void)
{
  uint8_t th[CMOX_SHA256_SIZE];
  uint8_t okm[64];
  size_t out_len = 0u;

  uint32_t t0 = DWT->CYCCNT;
  memcpy(transcript, pk, PK_LEN);
  memcpy(transcript + PK_LEN, ct, CT_LEN);
  if (cmox_hash_compute(CMOX_SHA256_ALGO, transcript, sizeof(transcript), th, sizeof(th), &out_len)
      != CMOX_HASH_SUCCESS)
  {
    return -1;
  }
  if (cmox_kdf_compute(CMOX_HKDF_SHA256_ALGO, ss, SS_LEN, th, sizeof(th),
                       (const uint8_t *)QL_KDF_INFO, sizeof(QL_KDF_INFO) - 1u,
                       okm, sizeof(okm), &out_len) != CMOX_KDF_SUCCESS)
  {
    return -1;
  }
  memcpy(k_pc2mcu, okm, 32u);
  memcpy(k_mcu2pc, okm + 32u, 32u);
  last_kdf_cycles = DWT->CYCCNT - t0;

  memset(okm, 0, sizeof(okm));
  memset(ss, 0, sizeof(ss));
  memset(sk, 0, sizeof(sk));     /* ephemeral key pair: not needed any more */
  seq_tx = 0u;
  seq_rx_last = 0u;
  session_ok = 1;
  return 0;
}

/* Encrypt and send one DATA frame MCU->PC. Returns cycles spent in AES-GCM. */
static uint32_t send_data(const uint8_t *msg, size_t len)
{
  uint8_t nonce[12], aad[9];
  size_t out_len = 0u;
  uint8_t *p = &tx_buf[5];

  if (len > QL_MAX_PLAINTEXT)
  {
    len = QL_MAX_PLAINTEXT;
  }
  seq_tx++;
  put_le64(p, seq_tx);
  make_nonce(nonce, 2u, seq_tx);
  aad[0] = QL_T_DATA;
  put_le64(&aad[1], seq_tx);

  uint32_t t0 = DWT->CYCCNT;
  cmox_cipher_retval_t rv = cmox_aead_encrypt(CMOX_AESFAST_GCMFAST_ENC_ALGO, msg, len, QL_TAG_LEN,
                                              k_mcu2pc, CMOX_CIPHER_256_BIT_KEY, nonce, sizeof(nonce),
                                              aad, sizeof(aad), p + 8, &out_len);
  uint32_t cyc = DWT->CYCCNT - t0;
  if (rv != CMOX_CIPHER_SUCCESS)
  {
    send_text(QL_T_ERR, "aes-gcm encrypt failed");
    return cyc;
  }
  frame_send(QL_T_DATA, p, (uint16_t)(8u + out_len));
  msgs_tx++;
  return cyc;
}

/* ======================================================================== */
/* Protocol handlers                                                         */
/* ======================================================================== */
static void send_stat_kem(const char *op)
{
  char line[160];
  uint32_t mhz = SystemCoreClock / 1000000u;
  snprintf(line, sizeof(line),
           "op=%s kem_cycles=%lu kem_us=%lu kdf_cycles=%lu kdf_us=%lu mhz=%lu",
           op, (unsigned long)last_kem_cycles, (unsigned long)(last_kem_cycles / mhz),
           (unsigned long)last_kdf_cycles, (unsigned long)(last_kdf_cycles / mhz),
           (unsigned long)mhz);
  send_text(QL_T_STAT, line);
}

static void send_confirm(void)
{
  char msg[96];
  snprintf(msg, sizeof(msg), "SESSION-OK %s role=%u", "ML-KEM-768", (unsigned)role);
  (void)send_data((const uint8_t *)msg, strlen(msg));
}

static void handle_hello(const uint8_t *p, uint16_t len)
{
  if (len < 18u || p[0] != QL_VERSION || p[1] > QL_ROLE_MCU_KEYGEN)
  {
    send_text(QL_T_ERR, "bad hello");
    return;
  }
  pqc_rng_mix(&p[2], 16u);            /* PC nonce as additional input */
  role = p[1];
  session_ok = 0;
  waiting_for = 0;

  uint8_t ack[2 + 16 + sizeof(QL_ALG_NAME)];
  ack[0] = QL_VERSION;
  ack[1] = role;
  randombytes(&ack[2], 16u);
  memcpy(&ack[18], QL_ALG_NAME, sizeof(QL_ALG_NAME) - 1u);
  frame_send(QL_T_HELLO_ACK, ack, (uint16_t)(18u + sizeof(QL_ALG_NAME) - 1u));

  if (role == QL_ROLE_PC_KEYGEN)
  {
    waiting_for = QL_T_PK;
  }
  else
  {
    uint32_t t0 = DWT->CYCCNT;
    int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
    last_kem_cycles = DWT->CYCCNT - t0;
    if (rc != 0)
    {
      send_text(QL_T_ERR, "keypair failed");
      return;
    }
    last_kdf_cycles = 0u;
    send_stat_kem("keygen");
    frame_send(QL_T_PK, pk, PK_LEN);
    waiting_for = QL_T_CT;
  }
}

static void handle_pk(const uint8_t *p, uint16_t len)
{
  if (waiting_for != QL_T_PK || len != PK_LEN)
  {
    send_text(QL_T_ERR, "unexpected PK");
    return;
  }
  memcpy(pk, p, PK_LEN);
  uint32_t t0 = DWT->CYCCNT;
  int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk);
  last_kem_cycles = DWT->CYCCNT - t0;
  if (rc != 0 || derive_session_keys() != 0)
  {
    send_text(QL_T_ERR, "encaps/kdf failed");
    return;
  }
  waiting_for = 0;
  frame_send(QL_T_CT, ct, CT_LEN);
  send_stat_kem("encaps");
  send_confirm();
}

static void handle_ct(const uint8_t *p, uint16_t len)
{
  if (waiting_for != QL_T_CT || len != CT_LEN)
  {
    send_text(QL_T_ERR, "unexpected CT");
    return;
  }
  memcpy(ct, p, CT_LEN);
  uint32_t t0 = DWT->CYCCNT;
  int rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);
  last_kem_cycles = DWT->CYCCNT - t0;
  if (rc != 0 || derive_session_keys() != 0)
  {
    send_text(QL_T_ERR, "decaps/kdf failed");
    return;
  }
  waiting_for = 0;
  send_stat_kem("decaps");
  send_confirm();
}

/* Application: simple commands, everything else is echoed back. */
static size_t app_handle(const char *cmd, size_t n, char *reply, size_t cap)
{
  if (n == 6u && memcmp(cmd, "led on", 6u) == 0)
  {
    HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_SET);
    return (size_t)snprintf(reply, cap, "LD2 ON");
  }
  if (n == 7u && memcmp(cmd, "led off", 7u) == 0)
  {
    HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_RESET);
    return (size_t)snprintf(reply, cap, "LD2 OFF");
  }
  if (n == 5u && memcmp(cmd, "stats", 5u) == 0)
  {
    return (size_t)snprintf(reply, cap, "rx=%lu tx=%lu auth_fail=%lu uptime_ms=%lu",
                            (unsigned long)msgs_rx, (unsigned long)msgs_tx,
                            (unsigned long)auth_fail, (unsigned long)HAL_GetTick());
  }
  if (n == 3u && memcmp(cmd, "uid", 3u) == 0)
  {
    const uint32_t *uid = (const uint32_t *)UID_BASE;
    return (size_t)snprintf(reply, cap, "UID %08lX-%08lX-%08lX",
                            (unsigned long)uid[0], (unsigned long)uid[1], (unsigned long)uid[2]);
  }
  int k = snprintf(reply, cap, "STM32 received %u B: ", (unsigned)n);
  size_t m = (n < cap - (size_t)k - 1u) ? n : cap - (size_t)k - 1u;
  memcpy(reply + k, cmd, m);
  reply[k + (int)m] = '\0';
  return (size_t)k + m;
}

static void handle_data(const uint8_t *p, uint16_t len)
{
  static uint8_t plain[QL_MAX_PLAINTEXT + 1u];
  static char reply[QL_MAX_PLAINTEXT + 64u];
  uint8_t nonce[12], aad[9];
  size_t out_len = 0u;

  if (!session_ok)
  {
    send_text(QL_T_ERR, "no session");
    return;
  }
  if (len < 8u + QL_TAG_LEN || len > 8u + QL_MAX_PLAINTEXT + QL_TAG_LEN)
  {
    send_text(QL_T_ERR, "bad data length");
    return;
  }
  uint64_t seq = get_le64(p);
  if (seq <= seq_rx_last)
  {
    send_text(QL_T_ERR, "replayed sequence number");
    return;
  }
  make_nonce(nonce, 1u, seq);
  aad[0] = QL_T_DATA;
  put_le64(&aad[1], seq);

  uint32_t t0 = DWT->CYCCNT;
  cmox_cipher_retval_t rv = cmox_aead_decrypt(CMOX_AESFAST_GCMFAST_DEC_ALGO, p + 8, len - 8u, QL_TAG_LEN,
                                              k_pc2mcu, CMOX_CIPHER_256_BIT_KEY, nonce, sizeof(nonce),
                                              aad, sizeof(aad), plain, &out_len);
  uint32_t dec_cyc = DWT->CYCCNT - t0;
  if (rv != CMOX_CIPHER_AUTH_SUCCESS)
  {
    auth_fail++;
    send_text(QL_T_ERR, "authentication failed (tag)");
    return;
  }
  seq_rx_last = seq;
  msgs_rx++;

  size_t rlen = app_handle((const char *)plain, out_len, reply, sizeof(reply));
  uint32_t enc_cyc = send_data((const uint8_t *)reply, rlen);

  char line[128];
  uint32_t mhz = SystemCoreClock / 1000000u;
  snprintf(line, sizeof(line), "op=data rx_len=%u dec_cycles=%lu dec_us=%lu tx_len=%u enc_cycles=%lu enc_us=%lu",
           (unsigned)out_len, (unsigned long)dec_cyc, (unsigned long)(dec_cyc / mhz),
           (unsigned)rlen, (unsigned long)enc_cyc, (unsigned long)(enc_cyc / mhz));
  send_text(QL_T_STAT, line);
}

/* ======================================================================== */
void kem_link_run(void)
{
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CYCCNT = 0u;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
  pqc_rng_reset();
  {
    uint32_t boot = DWT->CYCCNT ^ HAL_GetTick();
    pqc_rng_mix((const uint8_t *)&boot, sizeof(boot));
  }

  {
    char line[160];
    snprintf(line, sizeof(line), "qlink v%u ready: %s, SYSCLK=%lu MHz",
             (unsigned)QL_VERSION, QL_ALG_NAME, (unsigned long)(SystemCoreClock / 1000000u));
    send_text(QL_T_STAT, line);
  }

  for (;;)
  {
    uint8_t type = 0u;
    uint16_t len = frame_recv(&type);
    switch (type)
    {
      case QL_T_HELLO: handle_hello(rx_buf, len); break;
      case QL_T_PK:    handle_pk(rx_buf, len);    break;
      case QL_T_CT:    handle_ct(rx_buf, len);    break;
      case QL_T_DATA:  handle_data(rx_buf, len);  break;
      default:         send_text(QL_T_ERR, "unknown frame type"); break;
    }
  }
}
