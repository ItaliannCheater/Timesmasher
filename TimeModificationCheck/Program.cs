using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Threading;

namespace TimeModificationCheck {
    class Program {

        class CheckInfo {
            public CheckInfo(bool result, DateTime previousTime, DateTime newTime, DateTime? generatedAt, long? recordIdentifier) {
                this.Result = result;
                this.Previous = previousTime;
                this.New = newTime;
                this.Time = generatedAt;
                this.Id = recordIdentifier;
            }

            public CheckInfo(bool result) {
                this.Result = result;
            }

            public bool Result { get; }
            public DateTime Previous { get; }
            public DateTime New { get; }
            public DateTime? Time { get; }
            public long? Id { get; }

        };

        static void Main(string[] args) {

            Console.Title = "Timesmasher by @italianncheater";
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Analyzing logs...\n\n");
            Console.ForegroundColor = ConsoleColor.White;

            CheckInfo info = checkTimeModification();

            Thread.Sleep(2000);
            if (info.Result) {
                Console.WriteLine("[!] And u got exposed!");
                Console.WriteLine("Previous time: {0} | New time: {1}\nGenerated at: {2} | Record ID: {3}\n\n",
                    info.Previous, info.New, info.Time, info.Id);
            } else Console.WriteLine("[?] U seems to be legit!\n\n");

            Console.Write("Press ENTER to exit the program...");
            Console.ReadLine();
        }

        static CheckInfo checkTimeModification() {
            EventRecord entry;
            string logPath = @"C:\Windows\System32\winevt\Logs\Security.evtx";
            EventLogReader logReader = new EventLogReader(logPath, PathType.FilePath);
            DateTime pcStartTime = startTime();

            while ((entry = logReader.ReadEvent()) != null) {
                if (entry.Id != 4616) continue;
                if (entry.TimeCreated <= pcStartTime) continue;

                IList<EventProperty> properties = entry.Properties;
                DateTime previousTime = DateTime.Parse(properties[4].Value.ToString());
                DateTime newTime = DateTime.Parse(properties[5].Value.ToString());

                if (Math.Abs((previousTime - newTime).TotalMinutes) > 5)
                    return new CheckInfo(true, previousTime, newTime, entry.TimeCreated, entry.RecordId);
            }
            return new CheckInfo(false);
        }

        static DateTime startTime() {
            return DateTime.Now.AddMilliseconds(-Environment.TickCount);
        }
    }
}
