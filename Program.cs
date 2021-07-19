using System;
using Microsoft.Extensions.Configuration;

namespace SimpleDecript
{
    class Program
    {
        static void Main(string[] args)
        {
            bool next;
            do
            {
                Console.Write("Enter data: ");
                var data = Console.ReadLine();
                try
                {
                    var json = EncryptionHelpers.DecryptQueryString(data, GetDescrptionKey());
                    Console.WriteLine("");
                    Console.WriteLine("");
                    Console.WriteLine(json);
                    Console.WriteLine("");
                    Console.WriteLine("");
                }
                catch (Exception e)
                {
                    Console.WriteLine("");
                    Console.WriteLine("");
                    Console.WriteLine(e.Message);
                }

                Console.Write("Decrypt more? [y/n]: ");
                var choice = Console.ReadLine();
                next = choice.Equals("y", StringComparison.InvariantCultureIgnoreCase);
                Console.Clear();
            } while (next);
        }

        static string GetDescrptionKey()
        {
            IConfiguration config = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .Build();
            return config["EncryptionKey"];
        }
    }
}
