using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using pwcracker.hash;

namespace pwcracker
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("1 for Q1 2 for Q2, or 3 to compute SHA1 hash");
            var q = Console.ReadLine();
            if (q == "1")
            {
                Console.WriteLine("enter given ciphertext.");
                var input = Console.ReadLine();
                var c = new Crack(input, "ASCII");

                c.trySha1PIN();
            }
            else if (q == "2")
            {
                Console.WriteLine("enter given ciphertext");
                var input = Console.ReadLine();
                var c = new Crack(input, "ASCII");

                c.trySha1FULL();
            }
            else if (q == "3")
            {
                Console.WriteLine("enter plaintext, including salt");
                var input = Console.ReadLine();

                var d = Encoding.ASCII.GetBytes(input);
                SHA1 sha = new SHA1CryptoServiceProvider();
                var hash =  sha.ComputeHash(d);
                Console.WriteLine(Crack.ByteArrToStr(hash));

            }
            else
            {
                Console.WriteLine("I said 1 or 2 or 3");
            }
            Console.ReadLine();
        }
    }
}
