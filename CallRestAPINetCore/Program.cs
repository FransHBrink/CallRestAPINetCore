using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using System.Security;
using Microsoft.Extensions.DependencyInjection;
using CallRestAPINetCore;
using Microsoft.Extensions.Logging;
using NLog.Extensions.Logging;

namespace WebAPIClient
{
    class Program
    {
        private static readonly HttpClient client = new HttpClient();

        static void Main(string[] args)
        {
            Console.WriteLine("Pwned Password app!" + Environment.NewLine);
            string username = ReadUsername();
            string password = ReadPassword();

            GetPwnedPassword(username, password).Wait();

            NLog.LogManager.Shutdown();
        }

        private static string ReadUsername()
        {
            Console.WriteLine("Please enter a username");

            var password = Console.ReadLine();
            return password;
        }

        private static string ReadPassword()
        {
            Console.WriteLine("Please enter a password");

            var password = Console.ReadLine();
            return password;
        }

        private static async Task GetPwnedPassword(string username, string password)
        {
            StringBuilder passwordHash = CreateHashFrom(password);

            var passwordHashShort = passwordHash.ToString().Substring(Constants.hashStartIndex, Constants.hashLength);

            string kAnonimityPwnedPwString = await CallHaveIBeenPwnedAPI(passwordHashShort);

            List<KeyValuePair<string, string>> BreachedPasswordList = BuildPwnedPasswordList(kAnonimityPwnedPwString);

            SearchPwnedPasswordList(username, passwordHash, BreachedPasswordList);

            Console.ReadLine();
        }

        private static void SearchPwnedPasswordList(string username, StringBuilder passwordHash, List<KeyValuePair<string, string>> BreachedPasswordList)
        {
            var breached = BreachedPasswordList.Find(x => x.Key.ToLower() == passwordHash.ToString().Remove(Constants.hashStartIndex, Constants.hashLength));

            var servicesProvider = BuildDi();
            var logger = servicesProvider.GetRequiredService<Logger>();

            //TODO: Add scenario - Happy path: What if account was not breached?
            if (breached.Key != null)
            {
                Console.WriteLine($"\n\nWARNING!!!\r\n" +
                    $"This password was previously exposed in a data breach.\r\n" +
                    $"Should you use this password you could potentially also be at risk.\r\n" +
                    $"Please consider changing it to something unique and strong.");

                logger.LogWarningMessage("Warning", $"Unsafe password detected. User, {username} notified.");
            }
        }

        private static List<KeyValuePair<string, string>> BuildPwnedPasswordList(string kAnonimityPwnedPwString)
        {
            IEnumerable<string> pwnedPasswordList = kAnonimityPwnedPwString.Split(new[] { "\r\n" }, StringSplitOptions.None).ToList();

            List<KeyValuePair<string, string>> split = new List<KeyValuePair<string, string>>();
            foreach (var pwnedPassword in pwnedPasswordList)
            {
                var pwnedPass = pwnedPassword.Split(":", StringSplitOptions.None).ToList();
                split.Add(new KeyValuePair<string, string>(pwnedPass[0], pwnedPass[1]));
            }

            return split;
        }

        private static async Task<string> CallHaveIBeenPwnedAPI(string passwordHashShort)
        {
            return await client.GetStringAsync($"https://api.pwnedpasswords.com/range/{passwordHashShort}").ConfigureAwait(false);
        }

        private static StringBuilder CreateHashFrom(string password)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(password);

            SHA1 sha = SHA1.Create();
            byte[] hashBytes = sha.ComputeHash(bytes);

            var sb = new StringBuilder(hashBytes.Length * 2);

            foreach (byte hashbyte in hashBytes)
            {
                sb.Append(hashbyte.ToString("x2"));
            }
            return sb;
        }

        private static IServiceProvider BuildDi()
        {
            var services = new ServiceCollection();

            //Runner is the custom class
            services.AddTransient<Logger>();

            services.AddSingleton<ILoggerFactory, LoggerFactory>();
            services.AddSingleton(typeof(ILogger<>), typeof(Logger<>));
            services.AddLogging((builder) => builder.SetMinimumLevel(LogLevel.Trace));

            var serviceProvider = services.BuildServiceProvider();

            var loggerFactory = serviceProvider.GetRequiredService<ILoggerFactory>();

            //configure NLog
            loggerFactory.AddNLog(new NLogProviderOptions { CaptureMessageTemplates = true, CaptureMessageProperties = true });
            NLog.LogManager.LoadConfiguration("nlog.config");

            return serviceProvider;
        }
    }
}
