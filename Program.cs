using static Monocypher.Monocypher;


// Check for invalid arguments:
var invalidArgs = Array.FindAll(args, (arg) => { return !File.Exists(arg); });
if (invalidArgs.Length > 0)
{
    Console.WriteLine(
$@"
Some files could not be located:

{String.Join("\n", Array.ConvertAll<string, string>(invalidArgs, invalidArg => "\t" + invalidArg))}

Proceeding with other files, if any.
"
);
}

// Encrypt files:
var encryptArgs = Array.FindAll(args, (arg) => { return File.Exists(arg) && !arg.EndsWith(".vault"); });
if (encryptArgs.Length > 0)
{
    Console.ForegroundColor = ConsoleColor.DarkYellow;
    Console.WriteLine(
@"
------------------
- ENCRYPT FILES: -
------------------
"
    );
    Console.ResetColor();
    var encryptPassword = ReadEncryptPassword();
    Console.WriteLine();

    foreach (var arg in encryptArgs)
    {
        Console.Write($"Processing file: \"{arg}\"");
        Encrypt(arg, encryptPassword);
        Console.WriteLine(" - Done!");
    }
}

// Decrypt files:
var decryptArgs = Array.FindAll(args, (arg) => { return File.Exists(arg) && arg.EndsWith(".vault"); });
if (decryptArgs.Length > 0)
{
    Console.ForegroundColor = ConsoleColor.DarkYellow;
    Console.WriteLine(
@"
------------------
- DECRYPT FILES: -
------------------
"
    );
    Console.ResetColor();
    var decryptPassword = ReadDecryptPassword();
    Console.WriteLine();

    foreach (var arg in decryptArgs)
    {
        Console.Write($"Decrypting file: \"{arg}\"");
        Decrypt(arg, decryptPassword);
        Console.WriteLine(" - Done!");
    }
}

// --------------------- //

static void Encrypt(string path, string password)
{
    // Input:
    byte[] plain_text = File.ReadAllBytes(path);

    // Config:
    var (key, salt) = DeriveEncryptKey(System.Text.Encoding.UTF8.GetBytes(password));
    byte[] nonce = System.Security.Cryptography.RandomNumberGenerator.GetBytes(24);

    // Output:
    byte[] mac = new byte[16];
    byte[] cipher_text = new byte[plain_text.Length];

    crypto_lock(mac, cipher_text, key, nonce, plain_text);
    File.WriteAllBytes(path, salt.Concat(nonce.Concat(mac.Concat(cipher_text))).ToArray());
    File.Move(path, path + ".vault");
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
    var password = ReadPassword();
    Console.WriteLine("Repeat Password:");
    var repeated = ReadPassword();

    // Check:
    if (password == null)
    {
        throw new Exception("No password entered.");
    }
    else if (password != repeated)
    {
        throw new Exception("Passwords didn't match.");
    }
    else if (password.Length < 8)
    {
        throw new Exception("Password not long enough.");
    }
    else
    {
        return password;
    }
}

// --------------------- //

static void Decrypt(string path, string password)
{
    // Input:
    var content = File.ReadAllBytes(path);
    byte[] cipher_text = content[64..];

    // cipher_text

    // Config:
    byte[] salt = content[0..24]; // 24 bytes
    byte[] key = DeriveDecryptKey(System.Text.Encoding.UTF8.GetBytes(password), salt);
    byte[] nonce = content[24..48]; // 24 bytes
    byte[] mac = content[48..64]; // 16 bytes

    // Output:
    byte[] plain_text = new byte[cipher_text.Length];

    crypto_unlock(plain_text, key, nonce, mac, cipher_text);
    File.WriteAllBytes(path, plain_text);
    File.Move(path, path[..^6]);
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
    var password = ReadPassword();

    // Check:
    if (password == null)
    {
        throw new Exception("No password entered.");
    }
    else
    {
        return password;
    }
}

// --------------------- //

static string ReadPassword()
{
    var keys = new List<char>();
    while (true)
    {
        var key = Console.ReadKey(true);
        switch (key.Key)
        {
            case ConsoleKey.Backspace:
                if (keys.Count > 0)
                {
                    Console.Write("\b \b");
                    keys.RemoveAt(keys.Count - 1);
                }
                break;

            case ConsoleKey.Tab:
                Console.Write('\r' + new String(keys.ToArray()));
                continue;

            case ConsoleKey.Enter:
                Console.WriteLine();
                return new String(keys.ToArray());

            case ConsoleKey.Escape:
                Console.Write('\r' + new String(' ', keys.Count));
                keys.Clear();
                break;

            default:
                keys.Add(key.KeyChar);
                break;
        }
        Console.Write('\r' + new String('*', keys.Count));
    }
}
