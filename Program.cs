using static Monocypher.Monocypher;

foreach (var arg in args)
{
    // Check if file exists:
    if (!File.Exists(arg))
    {
        Console.WriteLine($"Invalid path: <<{arg}>>");
        continue;
    }

    // Check if file is encrypted/decrypted:
    if (arg.EndsWith(".vault"))
    {
        Console.WriteLine($"Decrypting: <<{arg}>>");
        Decrypt(arg);
    }
    else
    {
        Console.WriteLine($"Encrypting: <<{arg}>>");
        Encrypt(arg);
    }
}

// --------------------- //

static void Encrypt(string path)
{
    // Input:
    byte[] plain_text = File.ReadAllBytes(path);

    // Config:
    var (key, salt) = DeriveEncryptKey(System.Text.Encoding.UTF8.GetBytes(ReadEncryptPassword()));
    byte[] nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(24);

    // Output:
    byte[] mac = new byte[16];
    byte[] cipher_text = new byte[plain_text.Length];

    crypto_lock(mac, cipher_text, key, nonce, plain_text);
    File.WriteAllBytes(path + ".vault", salt.Concat(nonce.Concat(mac.Concat(cipher_text))).ToArray());
}

static (byte[], byte[]) DeriveEncryptKey(ReadOnlySpan<byte> password)
{
    // Input:
    ReadOnlySpan<byte> salt = System.Security.Cryptography.RandomNumberGenerator.GetBytes(24);

    // Config:
    const uint nb_blocks = 1_000_000;
    const uint nb_iterations = 3;

    // Output:
    Span<byte> hash = new byte[32];
    Span<byte> work_area = new byte[(int)nb_blocks * 1024];

    crypto_argon2i(hash, work_area, nb_blocks, nb_iterations, password, salt);

    return (hash.ToArray(), salt.ToArray());
}

static string ReadEncryptPassword()
{
    Console.WriteLine("Enter Password:");
    var password = Console.ReadLine();
    Console.WriteLine("Repeat Password:");
    var repeated = Console.ReadLine();

    // Check:
    if ((password != null) && (password == repeated) && (password.Length >= 8))
    {
        return password;
    }
    else
    {
        throw new Exception("Passwords didn't match.");
    }
}

// --------------------- //

static void Decrypt(string path)
{
    // Input:
    var content = File.ReadAllBytes(path);
    byte[] cipher_text = content[64..];

    // cipher_text

    // Config:
    byte[] salt = content[0..24]; // 24 bytes
    byte[] key = DeriveDecryptKey(System.Text.Encoding.UTF8.GetBytes(ReadDecryptPassword()), salt);
    byte[] nonce = content[24..48]; // 24 bytes
    byte[] mac = content[48..64]; // 16 bytes

    // Output:
    byte[] plain_text = new byte[cipher_text.Length];

    crypto_unlock(plain_text, key, nonce, mac, cipher_text);
    File.WriteAllBytes(path[..^6] + ".plain", plain_text);
}

static byte[] DeriveDecryptKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt)
{
    // Config:
    const uint nb_blocks = 1_000_000;
    const uint nb_iterations = 3;

    // Output:
    Span<byte> hash = new byte[32];
    Span<byte> work_area = new byte[(int)nb_blocks * 1024];

    crypto_argon2i(hash, work_area, nb_blocks, nb_iterations, password, salt);

    return (hash.ToArray());
}

static string ReadDecryptPassword()
{
    Console.WriteLine("Enter Password:");
    var password = Console.ReadLine();

    // Check:
    if (password != null)
    {
        return password;
    }
    else
    {
        throw new Exception("No password entered.");
    }
}
