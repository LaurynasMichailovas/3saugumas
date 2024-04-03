using System;
using System.IO;
using System.Numerics;
using System.Text;

class RSAEncryption
{
    public BigInteger p { get; private set; }
    public BigInteger q { get; private set; }
    public BigInteger n { get; private set; }
    public BigInteger Phi { get; private set; }
    public BigInteger e { get; private set; }
    public BigInteger d { get; private set; }
    private string publicKeyPath = "publicKey.txt";
    private string encryptedTextPath = "encryptedText.txt";

    private Tuple<BigInteger, BigInteger> FindPrimeFactors(BigInteger n)
    {
        for (BigInteger i = 2; i < n; i++)
        {
            if (n % i == 0)
            {
                BigInteger p = i;
                BigInteger q = n / i;
                if (IsPrime(p) && IsPrime(q))
                {
                    return Tuple.Create(p, q);
                }
            }
        }
        return Tuple.Create(BigInteger.Zero, BigInteger.Zero);
    }
    public RSAEncryption(BigInteger p, BigInteger q)
    {
        this.p = p;
        this.q = q;
        CalculateParameters();
    }

    private void CalculateParameters()
    {
        n = p * q;
        Phi = (p - 1) * (q - 1);
        e = FindE(Phi);
        d = ModInverse(e, Phi);
        SavePublicKey();
    }

    private BigInteger FindE(BigInteger phi)
    {
        BigInteger e = 3;
        while (GCD(e, phi) != 1)
        {
            e += 2;
        }
        return e;
    }

    private BigInteger GCD(BigInteger a, BigInteger b)
    {
        while (b != 0)
        {
            BigInteger temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    }

    private BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger m0 = m, y = 0, x = 1;

        if (m == 1)
            return 0;

        while (a > 1)
        {
            BigInteger q = a / m;
            BigInteger t = m;
            m = a % m; a = t;
            t = y;
            y = x - q * y;
            x = t;
        }

        if (x < 0)
            x += m0;

        return x;
    }
    private bool IsPrime(BigInteger number)
    {
        if (number < 2) return false;
        for (BigInteger i = 2; i * i <= number; i++)
        {
            if (number % i == 0) return false;
        }
        return true;
    }
    public BigInteger Encrypt(int msg)
    {
        return BigInteger.ModPow(msg, e, n);
    }

    public int Decrypt(BigInteger cipher)
    {
        return (int)BigInteger.ModPow(cipher, d, n);
    }
    public void EncryptText(string text)
    {
        using (StreamWriter file = new StreamWriter(encryptedTextPath))
        {
            StringBuilder encryptedTextBuilder = new StringBuilder();

            foreach (char c in text)
            {
                BigInteger encryptedValue = Encrypt(c);
                file.WriteLine(encryptedValue);
                encryptedTextBuilder.Append(encryptedValue.ToString() + " ");
            }

            Console.WriteLine("Encrypted text:");
            Console.WriteLine(encryptedTextBuilder.ToString().TrimEnd());
        }
    }
    public string DecryptText()
    {
        var factors = FindPrimeFactors(n);
        p = factors.Item1;
        q = factors.Item2;
        Phi = (p - 1) * (q - 1);
        d = ModInverse(e, Phi); // org e

        StringBuilder decryptedText = new StringBuilder();
        string[] encryptedValues = File.ReadAllLines(encryptedTextPath);
        foreach (string value in encryptedValues)
        {
            BigInteger encryptedValue = BigInteger.Parse(value);
            int decryptedValue = Decrypt(encryptedValue);
            decryptedText.Append((char)decryptedValue);
        }
        return decryptedText.ToString();
    }
    private void SavePublicKey()
    {
        using (StreamWriter file = new StreamWriter(publicKeyPath))
        {
            file.WriteLine($"n={n}");
            file.WriteLine($"e={e}");
        }
    }

    public static void Main(string[] args)
    {
        Console.WriteLine("Enter prime number p:");
        BigInteger p = BigInteger.Parse(Console.ReadLine() ?? "0");

        Console.WriteLine("Enter prime number q:");
        BigInteger q = BigInteger.Parse(Console.ReadLine() ?? "0");

        Console.WriteLine("Enter initial text:");
        string initialText = Console.ReadLine() ?? "";

        RSAEncryption rsa = new RSAEncryption(p, q);

        rsa.EncryptText(initialText);
        Console.WriteLine("Text encrypted and saved.");

        string decryptedText = rsa.DecryptText();
        Console.WriteLine($"Decrypted text: {decryptedText}");
        Console.ReadKey();
    }
}