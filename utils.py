import random
import time
import hashlib
import binascii
import aiomysql


MAX_INT_PRIVATE_KEY   = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def encode_Base58(b):
    """Encode bytes to a base58-encoded string"""
    # Convert big-endian bytes to integer
    n = int('0x0' + binascii.hexlify(b).decode('utf8'), 16)
    # Divide that integer into bas58
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(b58_digits[r])
    res = ''.join(res[::-1])
    # Encode leading zeros as base58 zeros
    czero = 0
    pad = 0
    for c in b:
        if c == czero:
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res


def decode_Base58(s):
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''
    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise Exception('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit
    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = binascii.unhexlify(h.encode('utf8'))
    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + res

def generate_private_key():
    q = time.time()
    rnd = random.SystemRandom()
    a = rnd.randint(0,MAX_INT_PRIVATE_KEY)
    i = int((time.time()%0.01)*100000)
    h = a.to_bytes(32,byteorder="big")
    while True:
        h = hashlib.sha256(h).digest()
        if i>1: i -= 1
        else:
            if int.from_bytes(h,byteorder="big")<MAX_INT_PRIVATE_KEY:
                break
    return h

def ripemd160(byte_string):
    h = hashlib.new('ripemd160')
    h.update(byte_string)
    return h.digest()

def pubkey_to_ripemd160(pubkey):
    return ripemd160(hashlib.sha256(pubkey).digest())

def ripemd160_to_address(h):
    h = b"\x00" + h
    h += hashlib.sha256(hashlib.sha256(h).digest()).digest()[:4]
    return encode_Base58(h)


async def initdb(cur):
    db = "Simple"

    await cur.execute("CREATE DATABASE IF NOT EXISTS %s;" % db)
    await cur.execute("USE %s;" % db)
    await cur.execute("""
                        CREATE TABLE IF NOT EXISTS `Block` (
                        `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
                        `height` INT(11) UNSIGNED NOT NULL,
                        `hash` BINARY(32) NOT NULL,
                        `previous_hash` BINARY(32) NOT NULL,
                        `next_hash` BINARY(32) DEFAULT NULL,
                        `timestamp` INT(11) UNSIGNED NOT NULL DEFAULT 0,
                        PRIMARY KEY (`id`)
                        )
                        ENGINE = InnoDB
                        DEFAULT CHARACTER SET = utf8
                        ROW_FORMAT = COMPRESSED
                        KEY_BLOCK_SIZE = 8;""")

    await cur.execute("""
                        CREATE TABLE IF NOT EXISTS `Transaction` (
                        `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
                        `height` INT(11) UNSIGNED DEFAULT NULL,
                        `hash` BINARY(32) NOT NULL,
                        `hash_crc32` INT(10) UNSIGNED NOT NULL,
                        `timestamp` INT(11) UNSIGNED NOT NULL DEFAULT 0,
                        `affected` tinyint(1) DEFAULT 0,
                        PRIMARY KEY (`id`),
                        INDEX (`hash_crc32` ASC)
                        )
                        ENGINE = InnoDB
                        DEFAULT CHARACTER SET = utf8
                        ROW_FORMAT = COMPRESSED
                        KEY_BLOCK_SIZE = 8;""")

    await cur.execute("""
                        CREATE TABLE IF NOT EXISTS `Address` (
                          `id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
                          `address` BINARY(20) NOT NULL,
                          `address_crc32` INT(10) UNSIGNED NOT NULL,

                          /* Balance chunk */
                          `balance` BIGINT(20) DEFAULT 0,
                          `available_balance` BIGINT(20) DEFAULT 0,
                          `pending` BIGINT(20) DEFAULT 0,

                          /* Amounts chunk */
                          `received` BIGINT(20) DEFAULT 0,
                          `sent` BIGINT(20) DEFAULT 0,

                          /* Transactions chunk */
                          `senttx` BIGINT(20) DEFAULT 0,
                          `received_tx` BIGINT(20) DEFAULT 0,
                          `pending_sent_tx` INT(11) DEFAULT 0,
                          `pending_received_tx` INT(11) DEFAULT 0,
                          `invalid_tx` BIGINT(20) DEFAULT 0,
                          `total_tx` BIGINT(20) DEFAULT 0,


                          `meta_data` JSON DEFAULT NULL,
                          PRIMARY KEY (`id`),
                          INDEX (`address_crc32` ASC)
                          )
                        ENGINE = InnoDB
                        DEFAULT CHARACTER SET = latin1
                        ROW_FORMAT = COMPRESSED
                        KEY_BLOCK_SIZE = 8;""")

    await cur.execute("""
                        CREATE TABLE IF NOT EXISTS `Transaction_monitoring` (
                          `id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
                          `hash` BINARY(32) NOT NULL,
                          `hash_crc32` INT(10) UNSIGNED NOT NULL,
                          `tx_id` BIGINT(20) UNSIGNED NOT NULL,
                          `amount` BIGINT(20) SIGNED NOT NULL,
                          `address_id` BIGINT(20) UNSIGNED NOT NULL,
                          `confirmations` TINYINT(1) NOT NULL DEFAULT 0,
                          `processed` TINYINT(1) NOT NULL DEFAULT 0,
                          `notify` TINYINT(1) NOT NULL DEFAULT 0,
                          PRIMARY KEY (`id`),
                          INDEX (`confirmations` ASC),
                          INDEX (`hash_crc32` ASC)
                            )
                        ENGINE = InnoDB
                        DEFAULT CHARACTER SET = latin1
                        ROW_FORMAT = COMPRESSED
                        KEY_BLOCK_SIZE = 8;""")

    await cur.execute("""
                        CREATE TABLE IF NOT EXISTS `AddressKey` (
                          `id` BIGINT(20) UNSIGNED NOT NULL,
                          `private_key` BINARY(32) NOT NULL,
                          PRIMARY KEY (`id`),
                          FOREIGN KEY (id) REFERENCES Address(id))
                        ENGINE = InnoDB
                        DEFAULT CHARACTER SET = latin1
                        ROW_FORMAT = COMPRESSED
                        KEY_BLOCK_SIZE = 8;""")

    await cur.execute("""
                        CREATE TABLE IF NOT EXISTS `Coin` (
                          `id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
                          `out_point` BINARY(36) NOT NULL,
                          `out_point_crc32` INT(10) UNSIGNED NOT NULL,
                          `private_key` BINARY(32) NOT NULL,
                          `script` BLOB NOT NULL,
                          `block_height` BIGINT(20) UNSIGNED DEFAULT NULL,
                          `amount` BIGINT(20) UNSIGNED DEFAULT 0,
                          `status` TINYINT(1) NOT NULL DEFAULT 0,
                          /* status:
                               0 - unconfrimed
                               1 - ready to spent
                               2 - spent unconfirmed
                               3 - spent confirmed
                               4 - disabled
                               5 - locked
                          */
                          `date` MEDIUMINT(8) UNSIGNED NOT NULL DEFAULT 0,
                          `timestamp` INT(11) UNSIGNED NOT NULL DEFAULT 0,
                          PRIMARY KEY (`id`),
                          INDEX (`out_point_crc32` ASC),
                          INDEX (`date` ASC)
                          )
                        ENGINE = InnoDB
                        DEFAULT CHARACTER SET = latin1
                        ROW_FORMAT = COMPRESSED
                        KEY_BLOCK_SIZE = 8;""")

    print("bd ok ")

async def check_aex(cur,hash):
    raw_hash = binascii.unhexlify(hash)
    await cur.execute("SELECT id FROM Transaction "
                      "WHERE hash_crc32 = crc32(%s) and hash = %s LIMIT 1", (raw_hash, raw_hash))
    row = await cur.fetchone()
    if row is None:
        return True
    else:
        return False