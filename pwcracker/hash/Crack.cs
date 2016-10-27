using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace pwcracker.hash
{
    public class Crack
    {
        private const string letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=";

        private string salt;
        private byte[] hash;
        private Encoding enc;
        private DateTime startDateTime;

        public Crack(string expect, string encoding)
        {
            this.salt = expect.Substring(0, 2);
            this.hash = StringToByteArray(expect.Substring(2));
            this.enc = Encoding.GetEncoding(encoding);
        }

        public async void trySha1FULL()
        {

            foreach (var d1 in letters)
            {
                foreach (var d2 in letters)
                {
                    foreach (var d3 in letters)
                    {
                        foreach (var d4 in letters)
                        {
                            foreach (var d5 in letters)
                            {
                                foreach (var d6 in letters)
                                {
                                    var str = d1.ToString() + d2 + d3 + d4 + d5 + d6;
                                    if (await tryFull(str))
                                    {
                                        Console.WriteLine(str);
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        public async Task<bool> tryFull(string str)
        {
            var d = str + salt;
            var data = enc.GetBytes(d);
            var sh = await getSha1(data);
            if (await compare(sh, hash))
            {
                Console.WriteLine(str);
                return true;
            }
            return false;
        }

        public async void trySha1PIN()
        {
            this.startDateTime  = DateTime.UtcNow;
            for (var s = 0; s <= 1; s++)
            {
                for (var i = 0; i < 10000; i++)
                {
                    string data;
                    var code = i.ToString("D4");
                    if (s == 0)
                    {
                        data = code + this.salt;
                    }
                    else
                    {
                        data = this.salt + code;
                    }
                    var barr = enc.GetBytes(data);
                    var sha = getSha1(barr);
                    if (await compare(await sha, hash))
                    {
                        Console.WriteLine("SHA1");
                        Console.WriteLine("Bytes are in order");
                        Console.WriteLine("plaintext is " + salt + code);
                        Console.Write("Format was: ");
                        Console.WriteLine(s == 0 ? "PIN|Salt" : "Salt|PIN");
                        Console.WriteLine((DateTime.UtcNow - startDateTime).TotalMilliseconds + "ms");
                        Console.WriteLine("PIN is " + code);
                        return;
                    }
                    var rev = getSha1(barr.Reverse().ToArray());
                    if (await compare(await rev, hash))
                    {
                        Console.WriteLine("SHA1");
                        Console.WriteLine("Bytes in reverse order");
                        Console.WriteLine("plaintext is " + salt + code);
                        Console.Write("Format was: ");
                        Console.WriteLine(s == 0 ? "PIN|Salt" : "Salt|PIN");
                        Console.WriteLine((DateTime.UtcNow - startDateTime).TotalMilliseconds + "ms");
                        Console.WriteLine("PIN is " + code);
                        return;
                    }
                }
            }

            Console.WriteLine("Tries Sha1 for 0000-9999");
            Console.WriteLine("Did not find");
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        private async Task<bool> compare(byte[] one, byte[] two)
        {
            if (one.Length != two.Length)
            {
                return false;
            }
            for (var i = 0; i < one.Length; i++)
            {
                if (one[i] != two[i])
                {
                    return false;
                }
            }
            return true;
        }
        
        public static async Task<byte[]> getSha1(byte[] data)
        {
            SHA1 sha = new SHA1CryptoServiceProvider();
            return sha.ComputeHash(data);
        }

        public static string ByteArrToStr(IEnumerable<byte> input)
        {
            var arr = input.ToArray();
            if (!BitConverter.IsLittleEndian)
            {
                Array.Reverse(arr);
            }
            return "0x" + BitConverter.ToString(arr).Replace("-", "");
        }
    }
}
